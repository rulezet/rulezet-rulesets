import "pe"
rule _MPEG_Video_file_2_ {
  meta:
    description = "MPEG Video file (2)"

  strings:
    $0 = { 00 00 01 B3 }

  condition:
    $0 at pe.entry_point
}