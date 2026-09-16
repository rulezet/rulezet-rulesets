rule PEiD_02981_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 5B 58 9D 5E 5F 5D 59 5F C3 }

  condition:
    $a
}