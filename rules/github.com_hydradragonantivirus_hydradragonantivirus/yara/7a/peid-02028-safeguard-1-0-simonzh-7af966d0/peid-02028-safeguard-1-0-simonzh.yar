rule PEiD_02028_Safeguard_1_0____Simonzh_ {
  meta:
    description = "[Safeguard 1.0 -> Simonzh]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 EB 29 }

  condition:
    $a
}