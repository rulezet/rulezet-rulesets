rule PEiD_01266_nBinder_v3_6_1_ {
  meta:
    description = "[nBinder v3.6.1]"
    ep_only     = "false"

  strings:
    $a = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }

  condition:
    $a
}