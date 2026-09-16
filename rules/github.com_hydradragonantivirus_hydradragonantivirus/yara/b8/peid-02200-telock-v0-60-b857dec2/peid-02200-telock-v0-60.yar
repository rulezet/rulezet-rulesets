rule PEiD_02200_tElock_v0_60_ {
  meta:
    description = "[tElock v0.60]"
    ep_only     = "true"

  strings:
    $a = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

  condition:
    $a
}