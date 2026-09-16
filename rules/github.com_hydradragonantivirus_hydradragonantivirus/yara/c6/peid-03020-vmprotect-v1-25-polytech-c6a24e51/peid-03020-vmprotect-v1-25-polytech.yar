rule PEiD_03020_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 9D 5D 5E 58 59 5B 5F 5A 5F C3 }

  condition:
    $a
}