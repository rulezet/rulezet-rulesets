rule PEiD_02970_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 59 5B 5E 5A 5F 58 5D 9D 58 C3 }

  condition:
    $a
}