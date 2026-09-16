rule PEiD_02764_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 51 50 9C 55 52 50 57 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 46 FF 24 85 ?? ?? ?? ?? 8B 06 8D 76 04 83 ED 04 89 45 00 E9 }

  condition:
    $a
}