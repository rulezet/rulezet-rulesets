rule PEiD_00665_eXPressor_1_0_beta____CGSoftLabs_ {
  meta:
    description = "[eXPressor 1.0 beta -> CGSoftLabs]"
    ep_only     = "true"

  strings:
    $a = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

  condition:
    $a
}