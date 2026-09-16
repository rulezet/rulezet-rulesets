rule PEiD_00558_EXE_joiner____Amok_ {
  meta:
    description = "[EXE joiner -> Amok]"
    ep_only     = "true"

  strings:
    $a = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }

  condition:
    $a
}