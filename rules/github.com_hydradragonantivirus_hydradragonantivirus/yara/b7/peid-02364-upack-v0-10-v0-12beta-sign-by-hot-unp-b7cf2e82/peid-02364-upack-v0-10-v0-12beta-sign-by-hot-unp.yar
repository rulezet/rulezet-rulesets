rule PEiD_02364_Upack_v0_10___v0_12Beta____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.10 - v0.12Beta -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { BE 48 01 ?? ?? ?? ?? ?? 95 A5 33 C0 }

  condition:
    $a
}