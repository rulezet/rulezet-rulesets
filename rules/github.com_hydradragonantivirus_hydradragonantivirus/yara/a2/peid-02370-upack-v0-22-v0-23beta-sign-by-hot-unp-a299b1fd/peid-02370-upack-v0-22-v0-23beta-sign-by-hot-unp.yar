rule PEiD_02370_Upack_v0_22___v0_23Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.22 ~ v0.23Beta -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }

  condition:
    $a
}