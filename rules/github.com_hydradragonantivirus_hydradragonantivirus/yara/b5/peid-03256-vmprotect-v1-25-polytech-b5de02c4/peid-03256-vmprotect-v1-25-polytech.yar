rule PEiD_03256_VMProtect_v1_25____PolyTech_ {
  meta:
    description = "[VMProtect v1.25 -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8A 06 8D 76 01 66 8B 04 07 83 ED 02 66 89 45 00 E9 }

  condition:
    $a
}