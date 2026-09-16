rule PEiD_03087_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 5A 5A 59 58 5D 5E 5D 5F 5B 9D C3 }

  condition:
    $a
}