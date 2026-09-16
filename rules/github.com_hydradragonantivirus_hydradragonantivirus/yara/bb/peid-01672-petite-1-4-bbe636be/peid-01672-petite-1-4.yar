rule PEiD_01672_Petite_1_4_ {
  meta:
    description = "[Petite 1.4]"
    ep_only     = "false"

  strings:
    $a = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

  condition:
    $a
}