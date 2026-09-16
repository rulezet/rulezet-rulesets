rule PEiD_00676_eXpressor_v1_0____CGSoftLabs_ {
  meta:
    description = "[eXpressor v1.0 -> CGSoftLabs]"
    ep_only     = "false"

  strings:
    $a = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 }

  condition:
    $a
}