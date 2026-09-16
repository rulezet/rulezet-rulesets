rule PEiD_02725_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 52 53 56 55 56 9C 57 51 50 68 00 00 00 00 8B 74 24 2C 89 E5 81 EC C0 00 00 00 89 E7 03 75 00 8A 06 0F B6 C0 83 C6 01 FF 24 85 ?? ?? ?? ?? 8B 75 00 83 C5 04 E9 }

  condition:
    $a
}