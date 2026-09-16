rule libavcodec_celp_math_exp2b__16_big_64_ {
  strings:
    $a0 = { 00 03 02 c8 05 90 08 56 0b 1d 0d e5 10 ae 13 76 16 40 19 09 1b d4 1e 9f 21 6a 24 36 27 02 29 d0 2c 9d 2f 6a 32 39 35 08 37 d7 3a a6 3d 76 40 47 43 18 45 ea 48 bc 4b 8f 4e 62 51 36 54 0a 56 de }

  condition:
    $a0
}