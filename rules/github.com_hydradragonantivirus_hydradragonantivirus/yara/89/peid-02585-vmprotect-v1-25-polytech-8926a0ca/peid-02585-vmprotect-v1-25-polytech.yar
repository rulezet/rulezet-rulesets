rule PEiD_02585_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 0F B6 06 83 ED 02 83 EE FF 66 89 45 00 E9 }

  condition:
    $a
}