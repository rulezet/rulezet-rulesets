rule libavcodec_COOK_cplscale6__flt32___32_big_252_ {
  strings:
    $a0 = { 3f 7f 7d 51 3f 7e 73 f3 3f 7d 65 02 3f 7c 50 30 3f 7b 35 27 3f 7a 13 8b 3f 78 ea f3 3f 77 ba ef 3f 76 83 01 3f 75 42 9e 3f 73 f9 29 3f 72 a5 f3 3f 71 48 37 3f 6f df 13 3f 6e 69 87 3f 6c e6 6b 3f 6b 54 67 3f 69 b1 e9 3f 67 fd 12 3f 66 33 a6 3f 64 52 ed 3f 62 57 8a 3f 60 3d 3e 3f 5d fe 92 3f 5b 94 40 3f 58 f4 47 3f 56 10 33 3f 52 d1 c5 3f 4f 13 6e 3f 4a 8b b3 3f 44 7c 32 3f 35 04 f3 3f 24 1a 35 3f 1c 8f 87 3f 16 84 87 3f 11 3a 60 3f 0c 67 17 3f 07 e4 93 3f 03 9b fd 3e fe fc 72 3e f7 01 12 3e ef 35 b0 3e e7 8d 88 3e df fe 0f 3e d8 7e 38 3e d1 05 eb 3e c9 8d a4 3e c2 0e 22 3e ba 80 24 3e b2 dc 25 3e ab 1a 0f 3e a3 30 ea 3e 9b 16 6c 3e 92 be 60 3e 8a 19 d4 3e 81 15 cc 3e 6f 32 62 3e 5b 02 7b 3e 45 35 a7 3e 2d 29 0f 3e 11 b9 03 3d e0 d0 48 3d 81 44 f8 }

  condition:
    $a0
}