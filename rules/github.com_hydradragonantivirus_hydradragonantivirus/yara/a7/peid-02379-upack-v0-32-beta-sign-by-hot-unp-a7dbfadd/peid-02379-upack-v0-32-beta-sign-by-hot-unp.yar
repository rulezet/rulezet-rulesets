rule PEiD_02379_Upack_v0_32_Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.32 Beta -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { BE 88 01 ?? ?? AD 50 ?? ?? AD 91 F3 A5 }

  condition:
    $a
}