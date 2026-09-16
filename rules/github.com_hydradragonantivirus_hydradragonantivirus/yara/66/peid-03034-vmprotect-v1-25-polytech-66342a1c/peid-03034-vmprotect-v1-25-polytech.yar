rule PEiD_03034_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 59 5A 9D 5F 5B 5B 5D 58 5E C3 }

  condition:
    $a
}