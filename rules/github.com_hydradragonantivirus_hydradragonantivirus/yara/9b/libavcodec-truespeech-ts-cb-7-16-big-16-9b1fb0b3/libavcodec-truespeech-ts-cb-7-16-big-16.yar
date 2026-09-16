rule libavcodec_truespeech_ts_cb_7__16_big_16_ {
  strings:
    $a0 = { ce f0 e4 f9 f6 bb 06 46 14 f5 23 ff 35 6f 4a 8d }

  condition:
    $a0
}