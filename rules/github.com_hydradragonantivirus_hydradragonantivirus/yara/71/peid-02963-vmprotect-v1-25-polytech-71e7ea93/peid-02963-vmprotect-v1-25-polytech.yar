rule PEiD_02963_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5B 5E 5D 9D 5B 59 5A 5F C3 }

  condition:
    $a
}