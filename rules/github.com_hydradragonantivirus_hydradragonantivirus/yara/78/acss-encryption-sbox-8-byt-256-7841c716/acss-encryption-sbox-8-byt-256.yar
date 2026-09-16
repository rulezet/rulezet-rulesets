rule ACSS_encryption_sbox__8_byt_256_ {
  strings:
    $a0 = { 33 3b 73 15 53 5b 13 75 3d 35 7d 1b 5d 55 1d 7b 67 6f 27 81 c7 cf 87 21 69 61 29 8f c9 c1 89 2f e3 eb a3 05 43 4b 03 a5 ed e5 ad 0b 4d 45 0d ab ea e2 aa 00 4a 42 0a a0 e8 e0 a8 02 48 40 08 a2 3e 36 7e 14 5e 56 1e 74 3c 34 7c 16 5c 54 1c 76 6a 62 2a 80 ca c2 8a 20 68 60 28 82 c8 c0 88 22 ee e6 ae 04 4e 46 0e a4 ec e4 ac 06 4c 44 0c a6 e7 ef a7 01 47 4f 07 a1 e9 e1 a9 0f 49 41 09 af 63 6b 23 85 c3 cb 83 25 6d 65 2d 8b cd c5 8d 2b 37 3f 77 11 57 5f 17 71 39 31 79 1f 59 51 19 7f b3 bb f3 95 d3 db 93 f5 bd b5 fd 9b dd d5 9d fb ba b2 fa 90 da d2 9a f0 b8 b0 f8 92 d8 d0 98 f2 6e 66 2e 84 ce c6 8e 24 6c 64 2c 86 cc c4 8c 26 3a 32 7a 10 5a 52 1a 70 38 30 78 12 58 50 18 72 be b6 fe 94 de d6 9e f4 bc b4 fc 96 dc d4 9c f6 b7 bf f7 91 d7 df 97 f1 b9 b1 f9 9f d9 d1 99 ff }

  condition:
    $a0
}