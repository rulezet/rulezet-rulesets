rule PEiD_02381_Upack_v0_33___v0_34_Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.33 ~ v0.34 Beta -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { ?? ?? ?? ?? 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

  condition:
    $a
}