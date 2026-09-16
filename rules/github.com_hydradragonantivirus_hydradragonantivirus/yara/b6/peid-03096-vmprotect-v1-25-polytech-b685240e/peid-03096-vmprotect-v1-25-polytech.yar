rule PEiD_03096_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 5F 5E 5D 58 58 59 9D C3 }

  condition:
    $a
}