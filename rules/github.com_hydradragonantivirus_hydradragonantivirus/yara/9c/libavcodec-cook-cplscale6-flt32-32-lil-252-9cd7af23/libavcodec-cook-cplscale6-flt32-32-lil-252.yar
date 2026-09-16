rule libavcodec_COOK_cplscale6__flt32___32_lil_252_ {
  strings:
    $a0 = { 51 7d 7f 3f f3 73 7e 3f 02 65 7d 3f 30 50 7c 3f 27 35 7b 3f 8b 13 7a 3f f3 ea 78 3f ef ba 77 3f 01 83 76 3f 9e 42 75 3f 29 f9 73 3f f3 a5 72 3f 37 48 71 3f 13 df 6f 3f 87 69 6e 3f 6b e6 6c 3f 67 54 6b 3f e9 b1 69 3f 12 fd 67 3f a6 33 66 3f ed 52 64 3f 8a 57 62 3f 3e 3d 60 3f 92 fe 5d 3f 40 94 5b 3f 47 f4 58 3f 33 10 56 3f c5 d1 52 3f 6e 13 4f 3f b3 8b 4a 3f 32 7c 44 3f f3 04 35 3f 35 1a 24 3f 87 8f 1c 3f 87 84 16 3f 60 3a 11 3f 17 67 0c 3f 93 e4 07 3f fd 9b 03 3f 72 fc fe 3e 12 01 f7 3e b0 35 ef 3e 88 8d e7 3e 0f fe df 3e 38 7e d8 3e eb 05 d1 3e a4 8d c9 3e 22 0e c2 3e 24 80 ba 3e 25 dc b2 3e 0f 1a ab 3e ea 30 a3 3e 6c 16 9b 3e 60 be 92 3e d4 19 8a 3e cc 15 81 3e 62 32 6f 3e 7b 02 5b 3e a7 35 45 3e 0f 29 2d 3e 03 b9 11 3e 48 d0 e0 3d f8 44 81 3d }

  condition:
    $a0
}