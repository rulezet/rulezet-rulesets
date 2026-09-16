rule YUV_to_RGB_dither_8x8_32__8_byt_64_ {
  strings:
    $a0 = { 11 09 17 0f 10 08 16 0e 05 1d 03 1b 04 1c 02 1a 15 0d 13 0b 14 0c 12 0a 00 18 06 1e 01 19 07 1f 10 08 16 0e 11 09 17 0f 04 1c 02 1a 05 1d 03 1b 14 0c 12 0a 15 0d 13 0b 01 19 07 1f 00 18 06 1e }

  condition:
    $a0
}