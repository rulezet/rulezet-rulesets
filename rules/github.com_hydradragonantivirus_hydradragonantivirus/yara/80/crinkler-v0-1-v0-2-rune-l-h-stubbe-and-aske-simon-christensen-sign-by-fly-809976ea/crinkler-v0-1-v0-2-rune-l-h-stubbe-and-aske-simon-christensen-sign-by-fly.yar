import "pe"
rule Crinkler_V0_1_V0_2____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_____Sign_By_fly {
  strings:
    $a0 = { B9 ?? ?? ?? ?? 01 C0 68 ?? ?? ?? ?? 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE ?? ?? ?? ?? E9 }

  condition:
    $a0 at pe.entry_point
}