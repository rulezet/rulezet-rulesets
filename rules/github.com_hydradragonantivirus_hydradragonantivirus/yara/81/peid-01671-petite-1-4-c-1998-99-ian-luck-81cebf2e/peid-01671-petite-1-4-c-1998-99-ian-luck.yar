rule PEiD_01671_Petite_1_4_____c_1998_99_Ian_Luck_ {
  meta:
    description = "[Petite 1.4 -> (c)1998-99 Ian Luck]"
    ep_only     = "true"

  strings:
    $a = { ?? ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 ?? ?? 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }

  condition:
    $a
}