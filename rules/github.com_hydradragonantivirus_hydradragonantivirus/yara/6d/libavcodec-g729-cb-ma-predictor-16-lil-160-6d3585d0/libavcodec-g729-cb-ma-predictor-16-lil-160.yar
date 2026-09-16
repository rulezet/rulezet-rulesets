rule libavcodec_G729_cb_ma_predictor__16_lil_160_ {
  strings:
    $a0 = { e5 20 95 23 d7 23 05 23 4a 23 61 23 3d 22 47 22 92 23 e1 21 6a 1b 15 1c d6 1d 8b 1c 14 1d d3 1c 7e 1b 2c 1b 12 1b d4 1a 60 15 7e 13 0e 14 39 14 7e 14 15 14 56 14 e7 13 de 12 1b 14 d8 0f d7 0b 36 0a d0 0b 64 0b 99 0a ed 0c a5 0c 29 0b 91 0d 35 1e c8 1e fc 1f ef 1f 37 20 2a 21 bd 21 99 21 a7 20 91 1d 72 10 d7 0b f8 09 91 0d 24 0f 0d 0f 58 10 3a 10 45 0f 80 0f 8e 0c 8a 07 21 05 5f 08 bd 09 51 09 c3 0a 92 0a ee 09 67 0b d0 0b 38 06 ac 03 5f 06 bb 06 2b 06 f2 07 24 08 79 07 29 0a }

  condition:
    $a0
}