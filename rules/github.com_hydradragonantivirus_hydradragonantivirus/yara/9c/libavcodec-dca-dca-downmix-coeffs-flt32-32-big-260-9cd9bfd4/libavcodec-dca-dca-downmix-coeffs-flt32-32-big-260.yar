rule libavcodec_dca_dca_downmix_coeffs__flt32___32_big_260_ {
  strings:
    $a0 = { 3f 80 00 00 3f 7d 11 d1 3f 78 bc 9c 3f 71 ad f9 3f 6a d2 98 3f 64 29 05 3f 5d af d7 3f 57 65 ac 3f 51 49 31 3f 4b 59 18 3f 45 94 21 3f 3f f9 11 3f 3a 86 b8 3f 35 3b ef 3f 30 17 96 3f 2b 18 96 3f 26 3d e0 3f 21 86 6c 3f 1c f1 39 3f 18 7d 50 3f 14 29 bf 3f 0f f5 9a 3f 0b df fd 3f 07 e8 0b 3f 04 0c ec 3f 00 4d ce 3e e4 b3 b6 3e cb d4 b4 3e b5 aa 1a 3e a1 e8 9b 3e 90 4d 1c 3e 80 9b cc 3e 65 3e bb 3e 4c 50 9b 3e 36 18 87 3e 22 4b 06 3e 10 a4 d3 3e 00 e9 f9 3d e5 ca 15 3d cc cc cd 3d b6 87 38 3d a2 ad ad 3d 90 fc bf 3d 81 38 56 3d 59 73 45 3d 36 f6 2b 3d 19 f1 69 3d 01 86 e2 3c d9 f7 73 3c b7 65 63 3c 9a 4e fc 3c 81 d5 9f 3c 5a 7b f1 3c 37 d4 dd 3c 1a ac c8 3c 02 24 8a 3b b8 44 9c 3b 82 73 a6 3b 38 b4 9f 3b 02 c2 f2 3a b9 24 e5 3a 83 12 6f 3a 03 62 1b 39 83 b1 f8 00 00 00 00 }

  condition:
    $a0
}