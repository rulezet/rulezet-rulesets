rule libfaad2_pan_pow_2_neg__flt32___32_big_160_ {
  strings:
    $a0 = { 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 64 28 e0 3f 64 28 e0 3f 4b 58 d5 3f 4b 58 d5 3f 4b 58 d5 3f 4b 58 d5 3f 4b 58 d5 3f 21 86 03 3f 0f f5 26 3f 0f f5 26 3f 35 3b 97 3f 21 86 03 3f 00 4d 50 3e b5 a9 0e 3e a1 e7 93 3f 21 86 03 3f 00 4d 50 3e b5 a9 0e 3e 65 3c d7 3e 36 1a 03 3f 0f f5 24 3e cb d3 a9 3e 65 3c d7 3e 00 ea c7 3d b6 88 02 3f 00 4d 50 3e 90 4c 1a 3e 10 a5 d5 3d 90 fd 2e 3d 23 10 8b 3e cb d3 a9 3e 4c 52 68 3d b6 88 0f 3d 23 10 8b 3c 91 ac 9b }

  condition:
    $a0
}