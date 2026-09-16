rule PEiD_02369_Upack_v0_21Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.21Beta -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { BE 88 01 ?? ?? AD 8B F8 ?? ?? ?? ?? 33 }

  condition:
    $a
}