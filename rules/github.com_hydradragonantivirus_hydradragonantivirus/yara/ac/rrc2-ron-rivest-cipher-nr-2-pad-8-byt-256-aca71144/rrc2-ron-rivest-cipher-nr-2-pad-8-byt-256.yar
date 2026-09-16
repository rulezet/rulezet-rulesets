rule RRC2___Ron_Rivest_Cipher_Nr__2_Pad__8_byt_256_ {
  strings:
    $a0 = { 9e ba df 61 40 91 be be 75 d9 a3 46 ce b0 b7 c2 92 2b f8 8d 03 36 48 df e9 99 5b d2 24 83 f4 a1 69 78 71 bf 71 56 13 f5 d5 dd 2b 1b f2 9d 49 d5 c1 5c a6 0a 17 c5 70 6e c1 1e 9c 33 7d 33 9e 43 c5 d7 3b da 6e f6 b5 00 87 4c a4 61 2f 57 ea 6c 90 7f 06 06 de ac 50 90 16 f5 cf 46 e3 b6 92 86 77 b0 49 3a 87 45 17 c6 00 aa 20 ab b0 81 5b 18 7e 4d f8 00 76 45 39 3c be ab d9 3d 88 a9 c4 54 a8 a7 a3 66 df 40 ae b2 a6 ef f2 c3 f9 5c 3b 26 f1 2e ec 1f 3b 72 17 32 77 ba 07 42 d4 61 de b6 e6 76 7a 56 69 5c b3 f3 ff bd df a4 c2 d7 62 2c 11 14 35 99 89 e0 b0 64 d0 72 24 c8 91 96 d7 14 57 2c fc 14 eb f2 a3 84 3f 12 05 7a 4a 61 22 61 8e 56 92 dd b3 a6 a1 4a 45 b6 58 78 80 3a 4c 9b 0f 1e 4d d8 a5 75 6b 5a a9 7f 8f b5 d0 89 c8 7f aa c3 1a 54 ff 84 96 3a 67 fa 78 dd ed 25 08 63 }

  condition:
    $a0
}