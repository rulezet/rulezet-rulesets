rule PEiD_02207_tElock_v0_85f_ {
  meta:
    description = "[tElock v0.85f]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

  condition:
    $a
}