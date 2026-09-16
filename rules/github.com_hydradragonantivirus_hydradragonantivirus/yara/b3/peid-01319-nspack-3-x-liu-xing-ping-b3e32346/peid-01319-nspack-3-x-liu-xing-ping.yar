rule PEiD_01319_NSPack_3_x____Liu_Xing_Ping_ {
  meta:
    description = "[NSPack 3.x -> Liu Xing Ping]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

  condition:
    $a
}