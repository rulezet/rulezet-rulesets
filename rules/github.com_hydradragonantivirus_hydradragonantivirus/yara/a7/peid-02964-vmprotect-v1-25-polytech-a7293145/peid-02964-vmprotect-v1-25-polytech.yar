rule PEiD_02964_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 5E 5A 59 5D 59 9D 5F 5B C3 }

  condition:
    $a
}