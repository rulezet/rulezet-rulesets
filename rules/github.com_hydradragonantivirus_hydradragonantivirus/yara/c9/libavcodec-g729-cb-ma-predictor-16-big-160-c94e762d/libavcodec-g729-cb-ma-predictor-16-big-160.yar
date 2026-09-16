rule libavcodec_G729_cb_ma_predictor__16_big_160_ {
  strings:
    $a0 = { 20 e5 23 95 23 d7 23 05 23 4a 23 61 22 3d 22 47 23 92 21 e1 1b 6a 1c 15 1d d6 1c 8b 1d 14 1c d3 1b 7e 1b 2c 1b 12 1a d4 15 60 13 7e 14 0e 14 39 14 7e 14 15 14 56 13 e7 12 de 14 1b 0f d8 0b d7 0a 36 0b d0 0b 64 0a 99 0c ed 0c a5 0b 29 0d 91 1e 35 1e c8 1f fc 1f ef 20 37 21 2a 21 bd 21 99 20 a7 1d 91 10 72 0b d7 09 f8 0d 91 0f 24 0f 0d 10 58 10 3a 0f 45 0f 80 0c 8e 07 8a 05 21 08 5f 09 bd 09 51 0a c3 0a 92 09 ee 0b 67 0b d0 06 38 03 ac 06 5f 06 bb 06 2b 07 f2 08 24 07 79 0a 29 }

  condition:
    $a0
}