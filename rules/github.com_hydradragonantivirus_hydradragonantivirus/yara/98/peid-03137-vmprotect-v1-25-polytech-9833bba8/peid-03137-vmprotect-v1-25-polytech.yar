rule PEiD_03137_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5B 5A 9D 5B 5F 5E 5D 58 59 59 C3 }

  condition:
    $a
}