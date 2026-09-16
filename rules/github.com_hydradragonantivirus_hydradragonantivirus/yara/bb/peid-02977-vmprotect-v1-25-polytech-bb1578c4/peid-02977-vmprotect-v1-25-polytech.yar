rule PEiD_02977_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5A 58 5B 5E 59 5D 9D 5F 59 C3 }

  condition:
    $a
}