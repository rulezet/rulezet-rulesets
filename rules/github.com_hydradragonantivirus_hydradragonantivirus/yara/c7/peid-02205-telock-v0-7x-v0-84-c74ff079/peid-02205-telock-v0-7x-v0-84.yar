rule PEiD_02205_tElock_v0_7x___v0_84_ {
  meta:
    description = "[tElock v0.7x - v0.84]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 C3 83 }

  condition:
    $a
}