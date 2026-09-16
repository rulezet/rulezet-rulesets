rule PEiD_02837_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 56 50 51 53 57 52 9C 51 55 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 8D 76 01 8D 0C 85 ?? ?? ?? ?? FF 21 66 8B 6D 00 E9 }

  condition:
    $a
}