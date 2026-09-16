rule PEiD_03160_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5F 9D 58 5B 5D 5A 5A 5E 59 C3 }

  condition:
    $a
}