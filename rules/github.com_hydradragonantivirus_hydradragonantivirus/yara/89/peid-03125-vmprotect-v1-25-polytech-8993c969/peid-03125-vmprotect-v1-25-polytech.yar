rule PEiD_03125_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 58 5F 5E 5B 59 5D 5A 9D 59 C3 }

  condition:
    $a
}