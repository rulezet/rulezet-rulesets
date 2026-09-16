rule PEiD_03097_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5B 5A 9D 58 5F 5E 5E 59 5D C3 }

  condition:
    $a
}