rule PEiD_03118_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5F 5E 9D 5F 59 5A 5D 58 5B C3 }

  condition:
    $a
}