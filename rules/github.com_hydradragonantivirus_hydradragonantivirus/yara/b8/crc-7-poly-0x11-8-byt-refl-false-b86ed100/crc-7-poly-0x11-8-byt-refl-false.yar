rule CRC_7_poly_0x11__8_byt_refl_False_ {
  strings:
    $a0 = { 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 01 10 23 32 45 54 67 76 89 98 ab ba cd dc ef fe 02 13 20 31 46 57 64 75 8a 9b a8 b9 ce df ec fd 03 12 21 30 47 56 65 74 8b 9a a9 b8 cf de ed fc 04 15 26 37 40 51 62 73 8c 9d ae bf c8 d9 ea fb 05 14 27 36 41 50 63 72 8d 9c af be c9 d8 eb fa 06 17 24 35 42 53 60 71 8e 9f ac bd ca db e8 f9 07 16 25 34 43 52 61 70 8f 9e ad bc cb da e9 f8 08 19 2a 3b 4c 5d 6e 7f 80 91 a2 b3 c4 d5 e6 f7 09 18 2b 3a 4d 5c 6f 7e 81 90 a3 b2 c5 d4 e7 f6 0a 1b 28 39 4e 5f 6c 7d 82 93 a0 b1 c6 d7 e4 f5 0b 1a 29 38 4f 5e 6d 7c 83 92 a1 b0 c7 d6 e5 f4 0c 1d 2e 3f 48 59 6a 7b 84 95 a6 b7 c0 d1 e2 f3 0d 1c 2f 3e 49 58 6b 7a 85 94 a7 b6 c1 d0 e3 f2 0e 1f 2c 3d 4a 5b 68 79 86 97 a4 b5 c2 d3 e0 f1 0f 1e 2d 3c 4b 5a 69 78 87 96 a5 b4 c3 d2 e1 f0 }

  condition:
    $a0
}