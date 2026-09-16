rule PEiD_02901_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 57 54 53 9C 55 52 50 56 51 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 89 E8 83 ED 02 66 89 45 00 E9 }

  condition:
    $a
}