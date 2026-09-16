rule PEiD_01308_nSPack_2_x____North_Star_Liu_Xing_Ping_ {
  meta:
    description = "[nSPack 2.x -> North Star/Liu Xing Ping]"
    ep_only     = "true"

  strings:
    $a = { FF FF 8B 4E 08 8D 56 10 8B 36 8B FE 83 F9 00 74 3F 8A 07 47 2C E8 3C 01 77 F7 8B 07 80 7A 01 }

  condition:
    $a
}