rule PEiD_03048_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5D 5F 59 59 5A 5E 5B 9D 58 C3 }

  condition:
    $a
}