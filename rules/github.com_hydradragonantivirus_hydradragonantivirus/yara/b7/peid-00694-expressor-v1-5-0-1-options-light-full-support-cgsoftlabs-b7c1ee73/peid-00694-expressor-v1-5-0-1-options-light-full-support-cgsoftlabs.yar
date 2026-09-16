rule PEiD_00694_eXPressor_v1_5_0_1__Options____Light__Full_support__CGSoftLabs_ {
  meta:
    description = "[eXPressor v1.5.0.1 (Options -> Light, Full support) CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 81 EC ?? 02 00 00 53 56 57 83 A5 ?? FD FF FF 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 }

  condition:
    $a
}