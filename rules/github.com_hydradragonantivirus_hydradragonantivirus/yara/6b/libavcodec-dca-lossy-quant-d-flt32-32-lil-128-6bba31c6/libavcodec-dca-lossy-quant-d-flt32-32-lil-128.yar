rule libavcodec_dca_lossy_quant_d__flt32___32_lil_128_ {
  strings:
    $a0 = { 00 00 00 00 cd cc cc 3f 00 00 80 3f cd cc 4c 3f 3d 0a 17 3f 00 00 00 3f 3d 0a d7 3e 7b 14 ae 3e 5c 8f 42 3e ae 47 e1 3d 8f c2 75 3d 29 5c 0f 3d e3 a5 9b 3c 58 39 34 3c f4 fd d4 3b 6f 12 83 3b 0a d7 23 3b 34 80 b7 3a 17 b7 51 3a fa ed eb 39 52 49 9d 39 07 42 32 39 ac c5 a7 38 ac c5 27 38 ac c5 a7 37 ac c5 27 37 ac c5 a7 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}