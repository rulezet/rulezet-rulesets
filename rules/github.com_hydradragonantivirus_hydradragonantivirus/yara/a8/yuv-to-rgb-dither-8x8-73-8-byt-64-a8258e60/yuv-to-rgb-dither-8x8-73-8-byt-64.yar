rule YUV_to_RGB_dither_8x8_73__8_byt_64_ {
  strings:
    $a0 = { 00 37 0e 44 03 3a 11 48 25 12 32 20 28 16 36 23 09 40 05 3b 0d 43 08 3f 2e 1b 29 17 31 1f 2c 1a 02 39 10 47 01 38 0f 46 27 15 34 22 26 13 33 21 0b 42 07 3e 0a 41 06 3c 30 1e 2b 19 2f 1d 2a 18 }

  condition:
    $a0
}