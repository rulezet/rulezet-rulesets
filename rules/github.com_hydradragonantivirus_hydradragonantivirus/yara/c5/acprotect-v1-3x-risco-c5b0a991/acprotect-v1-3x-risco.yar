import "pe"
rule ACProtect_V1_3X____risco {
  strings:
    $a0 = { 60 50 E8 01 00 00 00 75 83 }

  condition:
    $a0 at pe.entry_point
}