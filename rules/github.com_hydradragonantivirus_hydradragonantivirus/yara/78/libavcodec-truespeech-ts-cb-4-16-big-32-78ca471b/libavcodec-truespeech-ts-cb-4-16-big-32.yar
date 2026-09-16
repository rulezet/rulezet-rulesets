rule libavcodec_truespeech_ts_cb_4__16_big_32_ {
  strings:
    $a0 = { ab e7 bb a8 c8 1c d3 26 dd 0e e5 d4 ee 22 f6 18 fe 28 06 4f 0e b7 17 b8 21 aa 2d 8b 3b a2 4d f9 }

  condition:
    $a0
}