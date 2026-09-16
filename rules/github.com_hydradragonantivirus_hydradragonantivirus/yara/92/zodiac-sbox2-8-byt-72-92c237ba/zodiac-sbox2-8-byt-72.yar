rule Zodiac_sbox2__8_byt_72_ {
  strings:
    $a0 = { 12 4a 26 c8 d2 62 ce e7 2e c3 fb 7c 65 48 8f b8 76 3d a5 8e 86 57 bd bc 1f ef 0c e0 78 71 11 75 95 d9 9b 9e b9 a4 f7 02 7f 80 83 7e be 56 96 73 9f 88 2a 14 89 9a f9 dc 32 6d de 6a 84 72 d8 8a d7 e3 08 4e 1e b3 5d 50 }

  condition:
    $a0
}