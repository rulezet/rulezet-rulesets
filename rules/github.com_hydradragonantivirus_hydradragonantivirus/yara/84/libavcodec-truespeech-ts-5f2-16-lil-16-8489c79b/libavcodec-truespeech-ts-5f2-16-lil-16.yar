rule libavcodec_truespeech_ts_5F2__16_lil_16_ {
  strings:
    $a0 = { 00 60 00 48 00 36 80 28 60 1e c8 16 16 11 d1 0c }

  condition:
    $a0
}