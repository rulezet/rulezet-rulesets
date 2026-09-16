rule PEiD_01320_NsPack_V1_1____LiuXingPing_ {
  meta:
    description = "[NsPack V1.1 -> LiuXingPing]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

  condition:
    $a
}