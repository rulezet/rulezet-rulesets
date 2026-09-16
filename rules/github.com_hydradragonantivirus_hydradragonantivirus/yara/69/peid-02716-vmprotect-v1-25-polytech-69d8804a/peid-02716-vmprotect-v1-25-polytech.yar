rule PEiD_02716_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 51 53 50 57 9C 55 54 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 EE FF 0F B6 C0 FF 24 85 ?? ?? ?? ?? 89 EC 5B 5E 5D 5D 9D 5F 58 5B 59 5A C3 }

  condition:
    $a
}