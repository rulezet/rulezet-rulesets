rule libavcodec_truespeech_ts_5F2__16_big_16_ {
  strings:
    $a0 = { 60 00 48 00 36 00 28 80 1e 60 16 c8 11 16 0c d1 }

  condition:
    $a0
}