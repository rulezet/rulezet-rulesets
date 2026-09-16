rule PEiD_02683_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 51 55 52 9C 53 56 57 50 53 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 EE FF FF 24 85 ?? ?? ?? ?? 89 EC 5A 5B 58 5F 5E 5A 9D 5A 5D 59 C3 }

  condition:
    $a
}