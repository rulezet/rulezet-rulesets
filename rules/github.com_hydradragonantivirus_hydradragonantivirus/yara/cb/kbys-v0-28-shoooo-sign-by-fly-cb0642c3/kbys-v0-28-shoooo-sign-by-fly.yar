import "pe"
rule KByS_V0_28____shoooo_____Sign_By_fly {
  strings:
    $a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }

  condition:
    $a0 at pe.entry_point
}