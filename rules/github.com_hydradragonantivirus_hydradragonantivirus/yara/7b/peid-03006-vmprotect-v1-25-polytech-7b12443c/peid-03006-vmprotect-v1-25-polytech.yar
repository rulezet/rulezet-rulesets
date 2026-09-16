rule PEiD_03006_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5E 5B 59 5D 5F 9D 5A 58 5F C3 }

  condition:
    $a
}