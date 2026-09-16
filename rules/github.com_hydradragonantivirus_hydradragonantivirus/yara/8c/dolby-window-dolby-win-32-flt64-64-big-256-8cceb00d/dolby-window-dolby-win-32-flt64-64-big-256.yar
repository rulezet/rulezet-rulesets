rule Dolby_window_dolby_win_32__flt64___64_big_256_ {
  strings:
    $a0 = { 3f 16 f6 28 e5 9b 6f b8 3f 4e 8b a8 c6 27 58 a3 3f 6a 4e ec 13 1c e6 00 3f 80 97 40 61 9d 66 0e 3f 91 88 f6 1c 50 98 03 3f a0 6b c0 3c eb 90 37 3f ac 12 c7 dd f4 db ee 3f b6 4e 8e 8d 17 04 28 3f c0 ad 6b 60 de 4d fd 3f c7 aa a8 3a 37 4b 27 3f d0 0a 19 08 0f 4a ab 3f d4 de 9d bf 01 74 44 3f da 2b ef cb 4b 10 07 3f df bd 81 61 14 ed 3c 3f e2 ab 29 df 32 2b 8e 3f e5 5b d5 7d 65 91 22 3f e7 d4 22 bf 5b cb f4 3f e9 fd 74 68 38 46 6a 3f eb c9 92 65 25 eb 1d 3f ed 33 bb 83 9d 71 e1 3f ee 40 38 e0 40 43 ac 3f ee fa 90 87 12 89 be 3f ef 72 c1 47 d2 8d 7d 3f ef ba 2b 14 85 74 40 3f ef e0 d7 4a bf b0 29 3f ef f3 ad 2c 20 47 2b 3f ef fb c9 23 6d e3 a5 3f ef fe cc 80 44 64 2d 3f ef ff bb 2f 5b b4 39 3f ef ff f5 2f 7d 09 d2 3f ef ff ff 16 be 0c e3 3f ef ff ff fd f0 c4 46 }

  condition:
    $a0
}