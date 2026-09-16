rule PEiD_01017_Metrowerks_CodeWarrior_v2_0__GUI__ {
  meta:
    description = "[Metrowerks CodeWarrior v2.0 (GUI)]"
    ep_only     = "false"

  strings:
    $a = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

  condition:
    $a
}