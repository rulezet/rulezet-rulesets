rule PEiD_03270_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 06 83 ED 04 89 45 00 8D 76 04 E9 }

  condition:
    $a
}