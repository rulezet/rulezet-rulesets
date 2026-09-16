rule PEiD_02209_tElock_v0_92a_ {
  meta:
    description = "[tElock v0.92a]"
    ep_only     = "true"

  strings:
    $a = { E9 7E E9 FF FF 00 }

  condition:
    $a
}