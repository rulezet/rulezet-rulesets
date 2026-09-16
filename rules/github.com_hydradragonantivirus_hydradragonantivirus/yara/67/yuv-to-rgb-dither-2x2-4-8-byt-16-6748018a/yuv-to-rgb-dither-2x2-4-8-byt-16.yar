rule YUV_to_RGB_dither_2x2_4__8_byt_16_ {
  strings:
    $a0 = { 01 03 01 03 01 03 01 03 02 00 02 00 02 00 02 00 }

  condition:
    $a0
}