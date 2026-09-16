rule libavcodec_rv40_aic_table_index__16_big_40_ {
  strings:
    $a0 = { 00 00 01 00 02 00 00 11 01 11 02 11 05 11 06 11 00 22 01 22 02 22 07 22 02 72 02 27 08 22 02 82 02 28 01 12 01 16 02 21 }

  condition:
    $a0
}