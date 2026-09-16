rule PEiD_01306_NsPack_2_3____Liu_Xing_Ping_ {
  meta:
    description = "[NsPack 2.3 -> Liu Xing Ping]"
    ep_only     = "false"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 ?? ?? FF FF 8B 06 83 F8 00 74 11 8D B5 ?? ?? FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 ?? ?? FF FF 2B D0 89 95 ?? ?? FF FF 01 95 ?? ?? FF FF 8D B5 ?? ?? FF FF 01 16 8B 36 8B FD }

  condition:
    $a
}