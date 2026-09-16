import "pe"
rule _Can2Exe_v001_ {
  meta:
    description = "Can2Exe v0.01"

  strings:
    $0 = { 0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73 }

  condition:
    $0 at pe.entry_point
}