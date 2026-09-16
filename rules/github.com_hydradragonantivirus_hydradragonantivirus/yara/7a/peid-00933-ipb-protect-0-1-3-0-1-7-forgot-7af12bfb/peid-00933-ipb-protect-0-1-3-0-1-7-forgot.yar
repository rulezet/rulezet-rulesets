rule PEiD_00933_iPB_Protect_0_1_3___0_1_7____forgot_ {
  meta:
    description = "[iPB Protect 0.1.3 - 0.1.7 -> forgot]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }

  condition:
    $a
}