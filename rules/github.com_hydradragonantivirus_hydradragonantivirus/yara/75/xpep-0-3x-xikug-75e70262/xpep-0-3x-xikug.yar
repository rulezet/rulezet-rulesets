import "pe"
rule xPEP_0_3x____xIkUg {
  strings:
    $a0 = { 55 53 56 51 52 57 E8 16 00 00 00 }

  condition:
    $a0 at pe.entry_point
}