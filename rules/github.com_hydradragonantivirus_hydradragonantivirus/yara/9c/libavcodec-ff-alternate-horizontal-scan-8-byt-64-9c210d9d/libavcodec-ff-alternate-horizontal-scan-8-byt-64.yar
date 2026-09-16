rule libavcodec_ff_alternate_horizontal_scan__8_byt_64_ {
  strings:
    $a0 = { 00 01 02 03 08 09 10 11 0a 0b 04 05 06 07 0f 0e 0d 0c 13 12 18 19 20 21 1a 1b 14 15 16 17 1c 1d 1e 1f 22 23 28 29 30 31 2a 2b 24 25 26 27 2c 2d 2e 2f 32 33 38 39 3a 3b 34 35 36 37 3c 3d 3e 3f }

  condition:
    $a0
}