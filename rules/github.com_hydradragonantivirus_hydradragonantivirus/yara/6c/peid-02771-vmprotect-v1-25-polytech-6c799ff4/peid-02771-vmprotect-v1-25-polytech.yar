rule PEiD_02771_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 52 55 9C 57 56 51 50 54 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 8D 76 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5A 5E 58 59 5E 5F 9D 5D 5A 5B C3 }

  condition:
    $a
}