rule CRC_8_CCITT_poly_0xe1__8_byt_refl_True_ {
  strings:
    $a0 = { 00 32 64 56 c8 fa ac 9e 9f ad fb c9 57 65 33 01 31 03 55 67 f9 cb 9d af ae 9c ca f8 66 54 02 30 62 50 06 34 aa 98 ce fc fd cf 99 ab 35 07 51 63 53 61 37 05 9b a9 ff cd cc fe a8 9a 04 36 60 52 c4 f6 a0 92 0c 3e 68 5a 5b 69 3f 0d 93 a1 f7 c5 f5 c7 91 a3 3d 0f 59 6b 6a 58 0e 3c a2 90 c6 f4 a6 94 c2 f0 6e 5c 0a 38 39 0b 5d 6f f1 c3 95 a7 97 a5 f3 c1 5f 6d 3b 09 08 3a 6c 5e c0 f2 a4 96 87 b5 e3 d1 4f 7d 2b 19 18 2a 7c 4e d0 e2 b4 86 b6 84 d2 e0 7e 4c 1a 28 29 1b 4d 7f e1 d3 85 b7 e5 d7 81 b3 2d 1f 49 7b 7a 48 1e 2c b2 80 d6 e4 d4 e6 b0 82 1c 2e 78 4a 4b 79 2f 1d 83 b1 e7 d5 43 71 27 15 8b b9 ef dd dc ee b8 8a 14 26 70 42 72 40 16 24 ba 88 de ec ed df 89 bb 25 17 41 73 21 13 45 77 e9 db 8d bf be 8c da e8 76 44 12 20 10 22 74 46 d8 ea bc 8e 8f bd eb d9 47 75 23 11 }

  condition:
    $a0
}