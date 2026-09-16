rule PEiD_00170_Armadillo_v2_5x___v2_6x_ {
  meta:
    description = "[Armadillo v2.5x - v2.6x]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 ?? ?? ?? 33 D2 8A D4 89 15 EC }

  condition:
    $a
}