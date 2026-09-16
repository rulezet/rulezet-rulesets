rule PEiD_03033_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5E 58 5F 5D 59 5B C3 }

  condition:
    $a
}