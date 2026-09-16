rule CRC_8_poly_0xd3__8_byt_refl_False_ {
  strings:
    $a0 = { 00 d3 75 a6 ea 39 9f 4c 07 d4 72 a1 ed 3e 98 4b 0e dd 7b a8 e4 37 91 42 09 da 7c af e3 30 96 45 1c cf 69 ba f6 25 83 50 1b c8 6e bd f1 22 84 57 12 c1 67 b4 f8 2b 8d 5e 15 c6 60 b3 ff 2c 8a 59 38 eb 4d 9e d2 01 a7 74 3f ec 4a 99 d5 06 a0 73 36 e5 43 90 dc 0f a9 7a 31 e2 44 97 db 08 ae 7d 24 f7 51 82 ce 1d bb 68 23 f0 56 85 c9 1a bc 6f 2a f9 5f 8c c0 13 b5 66 2d fe 58 8b c7 14 b2 61 70 a3 05 d6 9a 49 ef 3c 77 a4 02 d1 9d 4e e8 3b 7e ad 0b d8 94 47 e1 32 79 aa 0c df 93 40 e6 35 6c bf 19 ca 86 55 f3 20 6b b8 1e cd 81 52 f4 27 62 b1 17 c4 88 5b fd 2e 65 b6 10 c3 8f 5c fa 29 48 9b 3d ee a2 71 d7 04 4f 9c 3a e9 a5 76 d0 03 46 95 33 e0 ac 7f d9 0a 41 92 34 e7 ab 78 de 0d 54 87 21 f2 be 6d cb 18 53 80 26 f5 b9 6a cc 1f 5a 89 2f fc b0 63 c5 16 5d 8e 28 fb b7 64 c2 11 }

  condition:
    $a0
}