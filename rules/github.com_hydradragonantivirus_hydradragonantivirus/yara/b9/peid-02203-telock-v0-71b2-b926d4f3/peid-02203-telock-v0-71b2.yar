rule PEiD_02203_tElock_v0_71b2_ {
  meta:
    description = "[tElock v0.71b2]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 44 11 00 00 C3 83 }

  condition:
    $a
}