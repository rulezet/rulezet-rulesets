rule PEiD_02388_Upack_V0_37_V0_39____Dwing_ {
  meta:
    description = "[Upack V0.37-V0.39 -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? ?? AD 50 FF ?? ?? EB }

  condition:
    $a
}