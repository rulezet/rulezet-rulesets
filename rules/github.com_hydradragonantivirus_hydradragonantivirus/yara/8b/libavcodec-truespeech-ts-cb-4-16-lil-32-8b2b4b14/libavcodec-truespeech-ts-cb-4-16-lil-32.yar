rule libavcodec_truespeech_ts_cb_4__16_lil_32_ {
  strings:
    $a0 = { e7 ab a8 bb 1c c8 26 d3 0e dd d4 e5 22 ee 18 f6 28 fe 4f 06 b7 0e b8 17 aa 21 8b 2d a2 3b f9 4d }

  condition:
    $a0
}