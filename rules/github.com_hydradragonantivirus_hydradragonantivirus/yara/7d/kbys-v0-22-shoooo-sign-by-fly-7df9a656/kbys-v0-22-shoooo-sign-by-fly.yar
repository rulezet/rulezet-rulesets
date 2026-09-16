import "pe"
rule KByS_V0_22____shoooo_____Sign_By_fly {
  strings:
    $a0 = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8 }

  condition:
    $a0 at pe.entry_point
}