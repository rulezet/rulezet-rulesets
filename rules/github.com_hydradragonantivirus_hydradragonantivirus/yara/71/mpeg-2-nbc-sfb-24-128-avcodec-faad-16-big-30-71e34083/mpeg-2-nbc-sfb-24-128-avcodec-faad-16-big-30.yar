rule MPEG_2_NBC_sfb_24_128__avcodec___faad___16_big_30_ {
  strings:
    $a0 = { 00 04 00 08 00 0c 00 10 00 14 00 18 00 1c 00 24 00 2c 00 34 00 40 00 4c 00 5c 00 6c 00 80 }

  condition:
    $a0
}