rule PEiD_00413_Crinkler_V0_3_V0_4____Rune_L_H_Stubbe_and_Aske_Simon_Christensen_ {
  meta:
    description = "[Crinkler V0.3-V0.4 -> Rune L.H.Stubbe and Aske Simon Christensen]"
    ep_only     = "true"

  strings:
    $a = { B8 00 00 42 00 31 DB 43 EB 58 }

  condition:
    $a
}