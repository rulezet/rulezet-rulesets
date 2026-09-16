rule PEiD_03041_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 59 5B 5E 59 5A 58 9D 5D 5B 5F C3 }

  condition:
    $a
}