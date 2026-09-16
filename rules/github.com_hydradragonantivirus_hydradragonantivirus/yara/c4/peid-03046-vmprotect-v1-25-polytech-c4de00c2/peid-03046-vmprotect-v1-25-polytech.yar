rule PEiD_03046_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5D 58 5F 59 5B 9D 5E 5A C3 }

  condition:
    $a
}