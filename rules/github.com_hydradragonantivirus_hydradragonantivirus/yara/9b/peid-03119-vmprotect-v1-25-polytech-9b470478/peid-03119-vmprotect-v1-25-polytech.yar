rule PEiD_03119_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 9D 5A 59 5E 5D 5F 5B 5A 58 C3 }

  condition:
    $a
}