rule libavcodec_truespeech_ts_cb_6__16_lil_16_ {
  strings:
    $a0 = { 50 b5 25 c8 80 d9 97 e9 83 f8 52 07 11 18 18 2e }

  condition:
    $a0
}