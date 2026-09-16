rule PEiD_03109_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5E 5B 5A 58 5D 59 5F 9D 5F C3 }

  condition:
    $a
}