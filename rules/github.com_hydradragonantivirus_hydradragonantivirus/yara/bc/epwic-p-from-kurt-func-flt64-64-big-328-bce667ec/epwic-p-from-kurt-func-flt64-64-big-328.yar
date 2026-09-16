rule EPWIC_p_from_kurt_func__flt64___64_big_328_ {
  strings:
    $a0 = { 3f d7 45 aa 2e 3c 53 6d 3f dc fb 3b 75 21 14 4d 3f e1 42 04 f2 ae 07 e6 3f e3 f8 50 df 15 a4 ad 3f e6 a5 0d 6b 22 8d ca 3f e9 4a f0 bf 1a 5c a3 3f eb eb c6 21 b7 e0 ac 3f ee 88 bb 90 64 66 b2 3f f0 91 53 79 fa 97 e1 3f f1 dd 1a 21 ea 35 93 3f f3 27 e5 21 57 68 9d 3f f4 71 de 69 ad 42 c4 3f f5 bb 2f ec 56 d5 d0 3f f7 03 ee a2 09 aa a4 3f f8 4c 2f 83 7b 4a 23 3f f9 94 07 89 61 3d 32 3f fa db 8b ac 71 0c b3 3f fc 22 bb ec aa b8 a6 3f fd 69 ad 42 c3 c9 ef 3f fe b0 5f ae bc 40 8e 3f ff f6 dd ac ee e0 f4 40 00 9e 93 9e ad d5 91 40 01 41 a3 6e 2e b1 c4 40 01 e4 a3 83 27 67 4d 40 02 87 8e 9f 6a 93 f3 40 03 2a 6f 3f 52 fc 26 40 03 cd 3a e6 85 db 77 40 04 6f fc 11 5d f6 55 40 05 12 b2 bf db 4c c2 40 05 b5 5e f1 fd de be 40 06 58 05 e5 f3 0e 80 40 06 fa 9d 1f 60 17 98 40 07 9d 2f 1a 9f be 77 40 08 3f b6 99 84 a0 e4 40 08 e2 38 da 3c 21 18 40 09 84 b5 dc c6 3f 14 40 0a 27 2d a1 22 fa d7 40 0a c9 a0 27 52 54 61 40 0b 6c 08 31 26 e9 79 40 0c 0e 70 3a fb 7e 91 40 0c b0 d3 06 a2 b1 70 }

  condition:
    $a0
}