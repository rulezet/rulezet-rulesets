rule PEiD_01030_MicroJoiner_1_1____coban2k_ {
  meta:
    description = "[MicroJoiner 1.1 -> coban2k]"
    ep_only     = "true"

  strings:
    $a = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

  condition:
    $a
}