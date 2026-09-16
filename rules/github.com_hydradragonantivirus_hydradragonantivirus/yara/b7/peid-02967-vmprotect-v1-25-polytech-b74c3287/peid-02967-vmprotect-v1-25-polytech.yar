rule PEiD_02967_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5A 5B 5E 58 5D 5F 9D 5B C3 }

  condition:
    $a
}