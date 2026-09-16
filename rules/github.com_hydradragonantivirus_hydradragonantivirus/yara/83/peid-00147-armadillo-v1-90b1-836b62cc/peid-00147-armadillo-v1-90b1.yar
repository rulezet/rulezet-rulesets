rule PEiD_00147_Armadillo_v1_90b1_ {
  meta:
    description = "[Armadillo v1.90b1]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}