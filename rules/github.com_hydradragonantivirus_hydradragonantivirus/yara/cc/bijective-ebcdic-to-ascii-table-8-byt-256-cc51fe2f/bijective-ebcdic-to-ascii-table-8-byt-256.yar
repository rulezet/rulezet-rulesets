rule bijective_ebcdic_to_ascii_table__8_byt_256_ {
  strings:
    $a0 = { 00 01 02 03 85 09 86 7f 87 8d 8e 0b 0c 0d 0e 0f 10 11 12 13 8f 0a 08 97 18 19 9c 9d 1c 1d 1e 1f 80 81 82 83 84 92 17 1b 88 89 8a 8b 8c 05 06 07 90 91 16 93 94 95 96 04 98 99 9a 9b 14 15 9e 1a 20 a0 e2 e4 e0 e1 e3 e5 e7 f1 60 2e 3c 28 2b 7c 26 e9 ea eb e8 ed ee ef ec df 21 24 2a 29 3b 9f 2d 2f c2 c4 c0 c1 c3 c5 c7 d1 5e 2c 25 5f 3e 3f f8 c9 ca cb c8 cd ce cf cc a8 3a 23 40 27 3d 22 d8 61 62 63 64 65 66 67 68 69 ab bb f0 fd fe b1 b0 6a 6b 6c 6d 6e 6f 70 71 72 aa ba e6 b8 c6 a4 b5 af 73 74 75 76 77 78 79 7a a1 bf d0 dd de ae a2 a3 a5 b7 a9 a7 b6 bc bd be ac 5b 5c 5d b4 d7 f9 41 42 43 44 45 46 47 48 49 ad f4 f6 f2 f3 f5 a6 4a 4b 4c 4d 4e 4f 50 51 52 b9 fb fc db fa ff d9 f7 53 54 55 56 57 58 59 5a b2 d4 d6 d2 d3 d5 30 31 32 33 34 35 36 37 38 39 b3 7b dc 7d da 7e }

  condition:
    $a0
}