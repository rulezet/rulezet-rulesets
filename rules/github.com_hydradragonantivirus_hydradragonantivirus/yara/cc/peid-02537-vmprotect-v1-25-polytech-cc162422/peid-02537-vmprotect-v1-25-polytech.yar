rule PEiD_02537_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 66 8B 55 00 83 C5 02 66 89 14 07 46 E9 }

  condition:
    $a
}