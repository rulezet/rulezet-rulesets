rule libavcodec_celp_math_tab_log2_G729_BITEXACT__16_big_66_ {
  strings:
    $a0 = { 00 00 05 af 0b 32 10 8c 15 c0 1a cf 1f bc 24 88 29 35 2d c4 32 37 36 8f 3a ce 3e f5 43 04 46 fc 4a df 4e ae 52 69 56 11 59 a7 5d 2c 60 9f 64 03 67 57 6a 9b 6d d1 70 fa 74 14 77 21 7a 22 7d 17 7f ff }

  condition:
    $a0
}