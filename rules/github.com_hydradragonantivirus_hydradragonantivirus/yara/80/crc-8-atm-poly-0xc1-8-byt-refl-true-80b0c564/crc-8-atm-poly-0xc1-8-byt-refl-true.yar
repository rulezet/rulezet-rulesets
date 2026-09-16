rule CRC_8_ATM_poly_0xc1__8_byt_refl_True_ {
  strings:
    $a0 = { 00 d9 b5 6c 6d b4 d8 01 da 03 6f b6 b7 6e 02 db b3 6a 06 df de 07 6b b2 69 b0 dc 05 04 dd b1 68 61 b8 d4 0d 0c d5 b9 60 bb 62 0e d7 d6 0f 63 ba d2 0b 67 be bf 66 0a d3 08 d1 bd 64 65 bc d0 09 c2 1b 77 ae af 76 1a c3 18 c1 ad 74 75 ac c0 19 71 a8 c4 1d 1c c5 a9 70 ab 72 1e c7 c6 1f 73 aa a3 7a 16 cf ce 17 7b a2 79 a0 cc 15 14 cd a1 78 10 c9 a5 7c 7d a4 c8 11 ca 13 7f a6 a7 7e 12 cb 83 5a 36 ef ee 37 5b 82 59 80 ec 35 34 ed 81 58 30 e9 85 5c 5d 84 e8 31 ea 33 5f 86 87 5e 32 eb e2 3b 57 8e 8f 56 3a e3 38 e1 8d 54 55 8c e0 39 51 88 e4 3d 3c e5 89 50 8b 52 3e e7 e6 3f 53 8a 41 98 f4 2d 2c f5 99 40 9b 42 2e f7 f6 2f 43 9a f2 2b 47 9e 9f 46 2a f3 28 f1 9d 44 45 9c f0 29 20 f9 95 4c 4d 94 f8 21 fa 23 4f 96 97 4e 22 fb 93 4a 26 ff fe 27 4b 92 49 90 fc 25 24 fd 91 48 }

  condition:
    $a0
}