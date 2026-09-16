rule PEiD_03408_Vx__Noon_1163_ {
  meta:
    description = "[Vx: Noon.1163]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 5B 50 56 B4 CB CD 21 3C 07 ?? ?? 81 ?? ?? ?? 2E ?? ?? 4D 5A ?? ?? BF 00 01 89 DE FC }

  condition:
    $a
}