rule PEiD_02206_tElock_v0_80_ {
  meta:
    description = "[tElock v0.80]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 F9 11 00 00 C3 83 }

  condition:
    $a
}