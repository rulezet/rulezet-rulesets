import "pe"
rule Exe_Shield_v2_7 {
  strings:
    $a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

  condition:
    $a0 at pe.entry_point
}