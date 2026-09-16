import "pe"
rule CrypKey_V5_6_X____Kenonic_Controls_Ltd______Sign_By_fly {
  strings:
    $a0 = { E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 00 75 07 6A 00 E8 }

  condition:
    $a0 at pe.entry_point
}