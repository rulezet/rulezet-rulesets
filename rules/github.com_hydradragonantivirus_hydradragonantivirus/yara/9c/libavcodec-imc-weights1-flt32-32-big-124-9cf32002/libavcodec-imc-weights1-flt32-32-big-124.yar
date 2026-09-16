rule libavcodec_imc_weights1__flt32___32_big_124_ {
  strings:
    $a0 = { 3d f4 ee 39 3d fc 28 70 3e 04 4a e8 3d cc 43 47 3d a7 c7 3f 3d c4 d8 19 3d b3 ca 75 3d b0 5e 52 3d b8 80 2a 3d cb 17 70 3d e7 67 d3 3e 06 45 e5 3e 1c 8e 26 3e 35 8c 09 3e 63 1a d2 3e 7a cb 86 3e 88 e6 d1 3e 9d 16 fd 3e a5 66 49 3e ac b1 46 3e bb c9 ac 3e c8 fd 3b 3e cb d0 9e 3e ce 7d 9a 3e d9 59 60 3e e3 b9 d0 3e e5 fb f8 3e e9 30 16 3e f4 a9 26 3f 00 2b d8 3f 02 a9 3f }

  condition:
    $a0
}