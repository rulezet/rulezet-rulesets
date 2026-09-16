rule libfaad2_pan_quant__flt32___32_big_160_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3e 2a 16 1e 3e 2a 16 1e 3e aa 16 1e 3e aa 16 1e 3e aa 16 1e 3e aa 16 1e 3e aa 16 1e 3f 2a 16 1e 3f 54 9b a6 3f 54 9b a6 3e ff 21 2d 3f 2a 16 1e 3f 7f 21 2d 3f bf 58 e2 3f d4 9b a6 3f 2a 16 1e 3f 7f 21 2d 3f bf 58 e2 40 0a 31 f9 40 1f 73 19 3f 54 9b a6 3f aa 16 1e 40 0a 31 f9 40 3f 57 3f 40 5f 3b 64 3f 7f 21 2d 3f e9 de 6a 40 34 b5 dd 40 74 7e 28 40 94 d2 89 3f aa 16 1e 40 14 d1 b7 40 5f 3b 64 40 94 d2 89 40 ba 07 5f }

  condition:
    $a0
}