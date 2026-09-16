rule PEiD_02373_Upack_v0_29_Beta___v0_31_Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.29 Beta ~ v0.31 Beta -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { BE 88 01 ?? ?? AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

  condition:
    $a
}