rule libavcodec_imc_exp_tab__flt64___64_big_256_ {
  strings:
    $a0 = { 3f 27 4e ea e3 7d 01 4c 3f 34 b9 6c 0f 20 43 11 3f 42 6d 42 bf 10 78 53 3f 50 62 4d d2 f1 a9 fc 3f 5d 22 a5 9c 5c 41 9f 3f 69 e7 c7 12 e8 53 d6 3f 77 08 93 6e d4 96 67 3f 84 7a e1 47 ae 14 7b 3f 92 35 a7 81 b9 a9 04 3f a0 30 dc 6b d1 34 66 3f ac ca b8 4a 89 bc 01 3f b9 99 99 99 99 99 9a 3f c6 c3 11 62 28 13 45 3f d4 3d 13 86 c5 81 7f 3f e1 fe b3 2e 96 15 81 3f f0 00 00 00 00 00 00 3f fc 73 d5 ba b2 18 16 40 09 4c 58 68 76 e1 df 40 16 7e 5f fa 3b 9a e1 40 24 00 00 00 00 00 00 40 31 c8 65 94 af 4f 0e 40 3f 9f 6e 82 94 9a 56 40 4c 1d f7 f8 ca 81 99 40 59 00 00 00 00 00 00 40 66 3a 7e f9 db 22 d1 40 73 c3 a5 11 9c e0 76 40 81 92 ba fb 7e 91 00 40 8f 40 00 00 00 00 00 40 9b c9 1e b8 51 eb 85 40 a8 b4 8e 56 04 18 93 40 b5 f7 69 ba 5e 35 3f 40 c3 88 00 00 00 00 00 }

  condition:
    $a0
}