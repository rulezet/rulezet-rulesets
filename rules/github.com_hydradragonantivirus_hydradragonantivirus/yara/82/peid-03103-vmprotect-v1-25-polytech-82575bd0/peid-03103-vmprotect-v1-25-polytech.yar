rule PEiD_03103_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5D 5E 58 5F 5A 59 5B 5B 9D C3 }

  condition:
    $a
}