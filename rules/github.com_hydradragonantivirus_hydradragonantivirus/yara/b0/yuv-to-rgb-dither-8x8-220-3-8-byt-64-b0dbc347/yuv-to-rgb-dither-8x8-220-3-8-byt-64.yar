rule YUV_to_RGB_dither_8x8_220_3__8_byt_64_ {
  strings:
    $a0 = { 00 7c 08 c1 00 8c 0c d5 37 0e 68 2a 42 13 77 34 03 a8 01 91 06 bb 03 a2 56 1f 46 15 63 27 52 1c 00 86 0b ce 00 81 09 c8 3e 11 72 30 3a 10 6d 2d 05 b5 02 9d 04 af 01 97 5f 24 4e 1a 5a 22 4a 18 }

  condition:
    $a0
}