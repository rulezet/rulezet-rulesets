rule libfaad2_drc_pow2_table__flt32___32_lil_188_ {
  strings:
    $a0 = { 2d c0 03 3f 7d 9c 07 3f c2 95 0b 3f d6 ac 0f 3f 99 e2 13 3f f0 37 18 3f c9 ad 1c 3f 18 45 21 3f d7 fe 25 3f 08 dc 2a 3f b7 dd 2f 3f f3 04 35 3f d8 52 3a 3f 87 c8 3f 3f 2a 67 45 3f f5 2f 4b 3f 24 24 51 3f fd 44 57 3f ce 93 5d 3f f0 11 64 3f c7 c0 6a 3f bf a1 71 3f 51 b6 78 3f 00 00 80 3f 2d c0 83 3f 7d 9c 87 3f c2 95 8b 3f d6 ac 8f 3f 99 e2 93 3f f0 37 98 3f c9 ad 9c 3f 18 45 a1 3f d7 fe a5 3f 08 dc aa 3f b7 dd af 3f f3 04 b5 3f d8 52 ba 3f 87 c8 bf 3f 2a 67 c5 3f f5 2f cb 3f 24 24 d1 3f fd 44 d7 3f ce 93 dd 3f f0 11 e4 3f c7 c0 ea 3f bf a1 f1 3f 51 b6 f8 3f }

  condition:
    $a0
}