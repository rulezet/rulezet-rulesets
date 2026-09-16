rule PEiD_02211_tElock_v0_96_ {
  meta:
    description = "[tElock v0.96]"
    ep_only     = "true"

  strings:
    $a = { E9 59 E4 FF FF 00 }

  condition:
    $a
}