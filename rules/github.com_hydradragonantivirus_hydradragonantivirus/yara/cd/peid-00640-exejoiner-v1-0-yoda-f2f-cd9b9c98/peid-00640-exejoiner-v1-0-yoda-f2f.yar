rule PEiD_00640_ExeJoiner_V1_0____Yoda_f2f_ {
  meta:
    description = "[ExeJoiner V1.0 -> Yoda f2f]"
    ep_only     = "true"

  strings:
    $a = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }

  condition:
    $a
}