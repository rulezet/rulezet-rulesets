import "pe"
rule ACProtect_V1_4X____risco {
  strings:
    $a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

  condition:
    $a0 at pe.entry_point
}