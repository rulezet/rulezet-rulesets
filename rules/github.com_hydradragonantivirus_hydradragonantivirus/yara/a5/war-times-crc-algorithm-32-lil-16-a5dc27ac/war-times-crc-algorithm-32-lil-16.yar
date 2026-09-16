rule War_Times_CRC_algorithm__32_lil_16_ {
  strings:
    $a0 = { 2e 16 00 00 d0 04 00 00 94 19 00 00 94 26 00 00 }

  condition:
    $a0
}