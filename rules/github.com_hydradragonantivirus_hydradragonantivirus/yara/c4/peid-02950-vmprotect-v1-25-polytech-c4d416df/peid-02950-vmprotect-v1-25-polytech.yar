rule PEiD_02950_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 8B 45 00 66 8B 55 02 F6 D0 F6 D2 83 ED 02 20 D0 66 89 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}