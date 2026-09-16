rule libavcodec_celp_math_exp2a__16_lil_64_ {
  strings:
    $a0 = { 00 00 9b 05 55 0b 30 11 2b 17 48 1d 88 23 ea 29 70 30 1a 37 ea 3d e0 44 fe 4b 43 53 b0 5a 48 62 0a 6a f7 71 11 7a 58 82 ce 8a 73 93 49 9c 50 a5 8a ae f7 b7 9a c1 72 cb 81 d5 c9 df 4b ea 07 f5 }

  condition:
    $a0
}