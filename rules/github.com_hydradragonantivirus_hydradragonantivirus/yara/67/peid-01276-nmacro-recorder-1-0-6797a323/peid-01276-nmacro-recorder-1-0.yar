rule PEiD_01276_nMacro_recorder_1_0_ {
  meta:
    description = "[nMacro recorder 1.0]"
    ep_only     = "false"

  strings:
    $a = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }

  condition:
    $a
}