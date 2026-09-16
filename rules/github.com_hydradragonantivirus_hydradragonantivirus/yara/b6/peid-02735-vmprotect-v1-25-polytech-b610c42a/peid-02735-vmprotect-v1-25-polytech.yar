rule PEiD_02735_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 55 56 51 53 50 9C 53 57 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 83 C6 01 0F B6 C0 FF 24 85 ?? ?? ?? ?? 8B 45 00 8B 55 04 83 C5 08 89 10 E9 }

  condition:
    $a
}