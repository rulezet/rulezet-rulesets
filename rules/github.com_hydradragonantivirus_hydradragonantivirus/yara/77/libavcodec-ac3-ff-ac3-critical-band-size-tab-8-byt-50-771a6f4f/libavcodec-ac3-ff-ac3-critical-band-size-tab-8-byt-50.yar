rule libavcodec_AC3_ff_ac3_critical_band_size_tab__8_byt_50_ {
  strings:
    $a0 = { 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 03 03 03 03 03 03 03 06 06 06 06 06 06 0c 0c 0c 0c 18 18 18 18 18 }

  condition:
    $a0
}