import "pe"
rule _JPEG_Graphics_format_p_description_ {
  meta:
    description = "JPEG Graphics format + description"

  strings:
    $0 = { FF D8 FF FE 00 27 }

  condition:
    $0 at pe.entry_point
}