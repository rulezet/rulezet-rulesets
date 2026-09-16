rule PEiD_02202_tElock_v0_71_ {
  meta:
    description = "[tElock v0.71]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ED 10 00 00 C3 83 }

  condition:
    $a
}