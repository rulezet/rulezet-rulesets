rule PEiD_00141_Armadillo_v1_80_ {
  meta:
    description = "[Armadillo v1.80]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a
}