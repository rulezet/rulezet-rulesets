rule libavcodec_dpcm_sol_table_old__8_byt_16_ {
  strings:
    $a0 = { 00 01 02 03 06 0A 0F 15 EB F1 F6 FA FD FE FF 00 }

  condition:
    $a0
}