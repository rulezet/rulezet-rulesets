rule PEiD_03044_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5F 5B 9D 59 5A 5D 58 5E C3 }

  condition:
    $a
}