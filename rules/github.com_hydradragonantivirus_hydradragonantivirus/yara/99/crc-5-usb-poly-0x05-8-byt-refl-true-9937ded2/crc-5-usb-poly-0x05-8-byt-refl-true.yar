rule CRC_5_USB_poly_0x05__8_byt_refl_True_ {
  strings:
    $a0 = { 00 51 a2 f3 05 54 a7 f6 0a 5b a8 f9 0f 5e ad fc 14 45 b6 e7 11 40 b3 e2 1e 4f bc ed 1b 4a b9 e8 28 79 8a db 2d 7c 8f de 22 73 80 d1 27 76 85 d4 3c 6d 9e cf 39 68 9b ca 36 67 94 c5 33 62 91 c0 50 01 f2 a3 55 04 f7 a6 5a 0b f8 a9 5f 0e fd ac 44 15 e6 b7 41 10 e3 b2 4e 1f ec bd 4b 1a e9 b8 78 29 da 8b 7d 2c df 8e 72 23 d0 81 77 26 d5 84 6c 3d ce 9f 69 38 cb 9a 66 37 c4 95 63 32 c1 90 a0 f1 02 53 a5 f4 07 56 aa fb 08 59 af fe 0d 5c b4 e5 16 47 b1 e0 13 42 be ef 1c 4d bb ea 19 48 88 d9 2a 7b 8d dc 2f 7e 82 d3 20 71 87 d6 25 74 9c cd 3e 6f 99 c8 3b 6a 96 c7 34 65 93 c2 31 60 f0 a1 52 03 f5 a4 57 06 fa ab 58 09 ff ae 5d 0c e4 b5 46 17 e1 b0 43 12 ee bf 4c 1d eb ba 49 18 d8 89 7a 2b dd 8c 7f 2e d2 83 70 21 d7 86 75 24 cc 9d 6e 3f c9 98 6b 3a c6 97 64 35 c3 92 61 30 }

  condition:
    $a0
}