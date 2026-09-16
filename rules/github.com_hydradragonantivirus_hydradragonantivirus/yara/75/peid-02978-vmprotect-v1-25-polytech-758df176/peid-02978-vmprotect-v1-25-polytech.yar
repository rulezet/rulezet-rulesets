rule PEiD_02978_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5E 5D 5B 5B 9D 59 5F C3 }

  condition:
    $a
}