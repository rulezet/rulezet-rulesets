rule PEiD_03288_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 8B 55 04 8A 4D 08 83 C5 02 0F A5 D0 89 45 04 9C 8F 45 00 E9 }

  condition:
    $a
}