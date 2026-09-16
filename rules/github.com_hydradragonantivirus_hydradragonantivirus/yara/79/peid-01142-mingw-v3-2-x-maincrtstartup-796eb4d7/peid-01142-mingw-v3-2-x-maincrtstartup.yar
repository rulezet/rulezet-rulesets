rule PEiD_01142_MinGW_v3_2_x___mainCRTStartup__ {
  meta:
    description = "[MinGW v3.2.x (_mainCRTStartup)]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

  condition:
    $a
}