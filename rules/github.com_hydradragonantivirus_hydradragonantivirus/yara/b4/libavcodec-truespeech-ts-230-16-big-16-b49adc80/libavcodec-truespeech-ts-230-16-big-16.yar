rule libavcodec_truespeech_ts_230__16_big_16_ {
  strings:
    $a0 = { 7f 3b 7e 78 7d b6 7c f5 7c 35 7b 76 7a b8 79 fc }

  condition:
    $a0
}