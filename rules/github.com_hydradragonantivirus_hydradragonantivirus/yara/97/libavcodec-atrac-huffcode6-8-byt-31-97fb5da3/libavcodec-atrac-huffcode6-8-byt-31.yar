rule libavcodec_atrac_huffcode6__8_byt_31_ {
  strings:
    $a0 = { 00 02 03 04 05 06 07 14 15 16 17 18 19 34 35 36 37 38 39 3a 3b 78 79 7a 7b 7c 7d 7e 7f 08 09 }

  condition:
    $a0
}