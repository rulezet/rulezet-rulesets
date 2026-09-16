rule MPEG_2_NBC_sfb_8_128__avcodec___faad___16_lil_30_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 3c 00 48 00 58 00 6c 00 80 00 }

  condition:
    $a0
}