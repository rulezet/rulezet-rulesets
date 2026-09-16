rule libavcodec_dca_lossy_quant_d__flt32___32_big_128_ {
  strings:
    $a0 = { 00 00 00 00 3f cc cc cd 3f 80 00 00 3f 4c cc cd 3f 17 0a 3d 3f 00 00 00 3e d7 0a 3d 3e ae 14 7b 3e 42 8f 5c 3d e1 47 ae 3d 75 c2 8f 3d 0f 5c 29 3c 9b a5 e3 3c 34 39 58 3b d4 fd f4 3b 83 12 6f 3b 23 d7 0a 3a b7 80 34 3a 51 b7 17 39 eb ed fa 39 9d 49 52 39 32 42 07 38 a7 c5 ac 38 27 c5 ac 37 a7 c5 ac 37 27 c5 ac 36 a7 c5 ac 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}