rule PEiD_03161_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 9D 59 5A 5B 58 5B 5F 5E 5D C3 }

  condition:
    $a
}