rule PEiD_02638_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 53 51 57 53 9C 52 55 56 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 8D 0C 85 ?? ?? ?? ?? FF 21 8B 45 00 36 8B 00 89 45 00 E9 }

  condition:
    $a
}