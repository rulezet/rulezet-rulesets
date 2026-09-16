rule libfaad2_pan_pow_2_neg__flt64___64_big_320_ {
  strings:
    $a0 = { 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f f0 00 00 00 00 00 00 3f ec 85 1b fe 63 47 ce 3f ec 85 1b fe 63 47 ce 3f e9 6b 1a 95 ad 7b cf 3f e9 6b 1a 95 ad 7b cf 3f e9 6b 1a 95 ad 7b cf 3f e9 6b 1a 95 ad 7b cf 3f e9 6b 1a 95 ad 7b cf 3f e4 30 c0 5c 7c 01 d9 3f e1 fe a4 b6 2d 4e 17 3f e1 fe a4 b6 2d 4e 17 3f e6 a7 72 d5 e0 71 c5 3f e4 30 c0 5c 7c 01 d9 3f e0 09 aa 02 9d 69 32 3f d6 b5 21 b5 5c 6d bf 3f d4 3c f2 64 36 0a 7e 3f e4 30 c0 5c 7c 01 d9 3f e0 09 aa 02 9d 69 32 3f d6 b5 21 b5 5c 6d bf 3f cc a7 9a e4 1c 74 ab 3f c6 c3 40 5c 10 a2 0f 3f e1 fe a4 80 7d 68 e1 3f d9 7a 75 11 24 14 b2 3f cc a7 9a e4 1c 74 ab 3f c0 1d 58 d6 5a eb 08 3f b6 d1 00 38 34 23 f4 3f e0 09 aa 02 9d 69 32 3f d2 09 83 36 80 c5 8d 3f c2 14 ba a2 27 dd 95 3f b2 1f a5 b7 b5 0d 93 3f a4 62 11 6d 0f cd d3 3f d9 7a 75 11 24 14 b2 3f c9 8a 4c f5 7c 18 7f 3f b6 d1 01 e5 b3 4d a0 3f a4 62 11 6d 0f cd d3 3f 92 35 93 5f c3 b4 f6 }

  condition:
    $a0
}