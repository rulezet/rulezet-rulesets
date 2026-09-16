rule PEiD_01322_NsPack_V1_4____LiuXingPing_ {
  meta:
    description = "[NsPack V1.4 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

  condition:
    $a
}