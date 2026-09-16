rule PEiD_03276_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 45 00 66 8B 55 04 83 C5 06 66 36 89 10 E9 }

  condition:
    $a
}