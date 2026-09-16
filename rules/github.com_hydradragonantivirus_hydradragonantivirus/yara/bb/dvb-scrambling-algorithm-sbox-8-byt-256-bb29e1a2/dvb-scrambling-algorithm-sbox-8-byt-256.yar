rule DVB_scrambling_algorithm_sbox__8_byt_256_ {
  strings:
    $a0 = { 3a ea 68 fe 33 e9 88 1a 83 cf e1 7f ba e2 38 12 e8 27 61 95 0c 36 e5 70 a2 06 82 7c 17 a3 26 49 be 7a 6d 47 c1 51 8f f3 cc 5b 67 bd cd 18 08 c9 ff 69 ef 03 4e 48 4a 84 3f b4 10 04 dc f5 5c c6 16 ab ac 4c f1 6a 2f 3c 3b d4 d5 94 d0 c4 63 62 71 a1 f9 4f 2e aa c5 56 e3 39 93 ce 65 64 e4 58 6c 19 42 79 dd ee 96 f6 8a ec 1e 85 53 45 de bb 7e 0a 9a 13 2a 9d c2 5e 5a 1f 32 35 9c a8 73 30 29 3d e7 92 87 1b 2b 4b a5 57 97 40 15 e6 bc 0e eb c3 34 2d b8 44 25 a4 1c c7 23 ed 90 6e 50 00 99 9e 4d d9 da 8d 6f 5f 3e d7 21 74 86 df 6b 05 8e 5d 37 11 d2 28 75 d6 a7 77 24 bf f0 b0 02 b7 f8 fc 81 09 b1 01 76 91 7d 0f c8 a0 f2 cb 78 60 d1 f7 e0 b5 98 22 b3 20 1d a6 db 7b 59 9f ae 31 fb d3 b6 ca 43 72 07 f4 d8 41 14 55 0d 54 8b b9 ad 46 0b af 80 52 2c fa 8c 89 66 fd b2 a9 9b c0 }

  condition:
    $a0
}