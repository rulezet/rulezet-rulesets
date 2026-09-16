rule PEiD_01310_nSPack_2_x_3_x__NET___North_Star_Liu_Xing_Ping_ {
  meta:
    description = "[nSPack 2.x/3.x .NET-> North Star/Liu Xing Ping]"
    ep_only     = "true"

  strings:
    $a = { FF 25 A4 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}