rule CRC_5_USB_poly_0x09__8_byt_refl_True_ {
  strings:
    $a0 = { 00 25 4a 6f 94 b1 de fb 09 2c 43 66 9d b8 d7 f2 12 37 58 7d 86 a3 cc e9 1b 3e 51 74 8f aa c5 e0 24 01 6e 4b b0 95 fa df 2d 08 67 42 b9 9c f3 d6 36 13 7c 59 a2 87 e8 cd 3f 1a 75 50 ab 8e e1 c4 48 6d 02 27 dc f9 96 b3 41 64 0b 2e d5 f0 9f ba 5a 7f 10 35 ce eb 84 a1 53 76 19 3c c7 e2 8d a8 6c 49 26 03 f8 dd b2 97 65 40 2f 0a f1 d4 bb 9e 7e 5b 34 11 ea cf a0 85 77 52 3d 18 e3 c6 a9 8c 90 b5 da ff 04 21 4e 6b 99 bc d3 f6 0d 28 47 62 82 a7 c8 ed 16 33 5c 79 8b ae c1 e4 1f 3a 55 70 b4 91 fe db 20 05 6a 4f bd 98 f7 d2 29 0c 63 46 a6 83 ec c9 32 17 78 5d af 8a e5 c0 3b 1e 71 54 d8 fd 92 b7 4c 69 06 23 d1 f4 9b be 45 60 0f 2a ca ef 80 a5 5e 7b 14 31 c3 e6 89 ac 57 72 1d 38 fc d9 b6 93 68 4d 22 07 f5 d0 bf 9a 61 44 2b 0e ee cb a4 81 7a 5f 30 15 e7 c2 ad 88 73 56 39 1c }

  condition:
    $a0
}