rule PEiD_03070_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 9D 5A 5F 58 5B 59 5B 5D 5E C3 }

  condition:
    $a
}