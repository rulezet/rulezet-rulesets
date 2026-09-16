rule PEiD_01405_Obsidium_V1_2_X____Obsidium_Software_ {
  meta:
    description = "[Obsidium V1.2.X -> Obsidium Software]"
    ep_only     = "true"

  strings:
    $a = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

  condition:
    $a
}