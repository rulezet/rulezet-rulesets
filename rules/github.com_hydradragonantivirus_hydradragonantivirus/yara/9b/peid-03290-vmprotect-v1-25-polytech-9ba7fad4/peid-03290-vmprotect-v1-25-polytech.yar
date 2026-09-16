rule PEiD_03290_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 F7 D0 F7 D2 21 D0 89 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}