rule PEiD_02959_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 EC 58 58 59 5E 5D 5B 9D 5F 5A 5E C3 }

  condition:
    $a
}