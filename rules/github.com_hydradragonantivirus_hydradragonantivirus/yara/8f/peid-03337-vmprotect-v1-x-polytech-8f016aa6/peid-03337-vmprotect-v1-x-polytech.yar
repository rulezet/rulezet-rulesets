rule PEiD_03337_VMProtect_V1_X____PolyTech_ {
  meta:
    description = "[VMProtect V1.X -> PolyTech]"
    ep_only     = "false"

  strings:
    $a = { 9C 60 68 00 00 00 00 8B 74 24 28 BF ?? ?? ?? ?? FC 89 F3 03 34 24 AC 00 D8 }

  condition:
    $a
}