rule PEiD_01323_nSpack_V2_3____LiuXingPing_ {
  meta:
    description = "[nSpack V2.3 -> LiuXingPing]"
    ep_only     = "false"

  strings:
    $a = { 9C 60 70 61 63 6B 24 40 }

  condition:
    $a
}