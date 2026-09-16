rule YUV_to_RGB_dither_2x2_8__8_byt_16_ {
  strings:
    $a0 = { 06 02 06 02 06 02 06 02 00 04 00 04 00 04 00 04 }

  condition:
    $a0
}