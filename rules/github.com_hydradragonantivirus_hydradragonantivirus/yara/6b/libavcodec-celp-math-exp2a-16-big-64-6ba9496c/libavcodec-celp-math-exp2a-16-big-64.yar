rule libavcodec_celp_math_exp2a__16_big_64_ {
  strings:
    $a0 = { 00 00 05 9b 0b 55 11 30 17 2b 1d 48 23 88 29 ea 30 70 37 1a 3d ea 44 e0 4b fe 53 43 5a b0 62 48 6a 0a 71 f7 7a 11 82 58 8a ce 93 73 9c 49 a5 50 ae 8a b7 f7 c1 9a cb 72 d5 81 df c9 ea 4b f5 07 }

  condition:
    $a0
}