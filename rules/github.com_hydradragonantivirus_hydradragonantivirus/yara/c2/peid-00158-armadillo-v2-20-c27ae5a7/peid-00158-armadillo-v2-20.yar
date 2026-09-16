rule PEiD_00158_Armadillo_v2_20_ {
  meta:
    description = "[Armadillo v2.20]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}