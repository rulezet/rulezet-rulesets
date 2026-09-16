rule PEiD_03094_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 58 5D 5E 5F 9D 5A 59 5A C3 }

  condition:
    $a
}