rule CRC_5_CCITT_poly_0x15__8_byt_refl_False_ {
  strings:
    $a0 = { 00 15 2a 3f 54 41 7e 6b a8 bd 82 97 fc e9 d6 c3 45 50 6f 7a 11 04 3b 2e ed f8 c7 d2 b9 ac 93 86 8a 9f a0 b5 de cb f4 e1 22 37 08 1d 76 63 5c 49 cf da e5 f0 9b 8e b1 a4 67 72 4d 58 33 26 19 0c 01 14 2b 3e 55 40 7f 6a a9 bc 83 96 fd e8 d7 c2 44 51 6e 7b 10 05 3a 2f ec f9 c6 d3 b8 ad 92 87 8b 9e a1 b4 df ca f5 e0 23 36 09 1c 77 62 5d 48 ce db e4 f1 9a 8f b0 a5 66 73 4c 59 32 27 18 0d 02 17 28 3d 56 43 7c 69 aa bf 80 95 fe eb d4 c1 47 52 6d 78 13 06 39 2c ef fa c5 d0 bb ae 91 84 88 9d a2 b7 dc c9 f6 e3 20 35 0a 1f 74 61 5e 4b cd d8 e7 f2 99 8c b3 a6 65 70 4f 5a 31 24 1b 0e 03 16 29 3c 57 42 7d 68 ab be 81 94 ff ea d5 c0 46 53 6c 79 12 07 38 2d ee fb c4 d1 ba af 90 85 89 9c a3 b6 dd c8 f7 e2 21 34 0b 1e 75 60 5f 4a cc d9 e6 f3 98 8d b2 a7 64 71 4e 5b 30 25 1a 0f }

  condition:
    $a0
}