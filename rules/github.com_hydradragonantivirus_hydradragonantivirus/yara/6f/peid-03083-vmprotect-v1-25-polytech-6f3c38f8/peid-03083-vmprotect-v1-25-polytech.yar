rule PEiD_03083_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 59 5D 5D 5A 5F 5E 58 9D 5B C3 }

  condition:
    $a
}