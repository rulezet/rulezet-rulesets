rule PEiD_02999_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 5D 5E 5B 5F 58 5E 59 5A 9D C3 }

  condition:
    $a
}