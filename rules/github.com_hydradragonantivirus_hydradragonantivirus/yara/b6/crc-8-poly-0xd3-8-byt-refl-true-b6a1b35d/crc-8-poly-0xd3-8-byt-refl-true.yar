rule CRC_8_poly_0xd3__8_byt_refl_True_ {
  strings:
    $a0 = { 00 0e 1c 12 38 36 24 2a 70 7e 6c 62 48 46 54 5a e0 ee fc f2 d8 d6 c4 ca 90 9e 8c 82 a8 a6 b4 ba 57 59 4b 45 6f 61 73 7d 27 29 3b 35 1f 11 03 0d b7 b9 ab a5 8f 81 93 9d c7 c9 db d5 ff f1 e3 ed ae a0 b2 bc 96 98 8a 84 de d0 c2 cc e6 e8 fa f4 4e 40 52 5c 76 78 6a 64 3e 30 22 2c 06 08 1a 14 f9 f7 e5 eb c1 cf dd d3 89 87 95 9b b1 bf ad a3 19 17 05 0b 21 2f 3d 33 69 67 75 7b 51 5f 4d 43 cb c5 d7 d9 f3 fd ef e1 bb b5 a7 a9 83 8d 9f 91 2b 25 37 39 13 1d 0f 01 5b 55 47 49 63 6d 7f 71 9c 92 80 8e a4 aa b8 b6 ec e2 f0 fe d4 da c8 c6 7c 72 60 6e 44 4a 58 56 0c 02 10 1e 34 3a 28 26 65 6b 79 77 5d 53 41 4f 15 1b 09 07 2d 23 31 3f 85 8b 99 97 bd b3 a1 af f5 fb e9 e7 cd c3 d1 df 32 3c 2e 20 0a 04 16 18 42 4c 5e 50 7a 74 66 68 d2 dc ce c0 ea e4 f6 f8 a2 ac be b0 9a 94 86 88 }

  condition:
    $a0
}