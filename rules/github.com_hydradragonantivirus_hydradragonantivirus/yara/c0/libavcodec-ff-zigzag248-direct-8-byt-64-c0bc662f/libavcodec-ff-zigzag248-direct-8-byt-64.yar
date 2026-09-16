rule libavcodec_ff_zigzag248_direct__8_byt_64_ {
  strings:
    $a0 = { 00 08 01 09 10 18 02 0a 11 19 20 28 30 38 21 29 12 1a 03 0b 04 0c 13 1b 22 2a 31 39 32 3a 23 2b 14 1c 05 0d 06 0e 15 1d 24 2c 33 3b 34 3c 25 2d 16 1e 07 0f 17 1f 26 2e 35 3d 36 3e 27 2f 37 3f }

  condition:
    $a0
}