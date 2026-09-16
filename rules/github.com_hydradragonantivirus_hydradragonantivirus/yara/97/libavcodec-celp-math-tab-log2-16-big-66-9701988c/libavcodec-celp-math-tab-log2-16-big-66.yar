rule libavcodec_celp_math_tab_log2__16_big_66_ {
  strings:
    $a0 = { 00 04 05 b3 0b 36 10 90 15 c4 1a d3 1f bf 24 8b 29 38 2d c7 32 3a 36 93 3a d1 3e f8 43 06 46 ff 4a e2 4e b1 52 6c 56 14 59 aa 5d 2e 60 a2 64 05 67 59 6a 9e 6d d4 70 fc 74 17 77 24 7a 25 7d 19 80 01 }

  condition:
    $a0
}