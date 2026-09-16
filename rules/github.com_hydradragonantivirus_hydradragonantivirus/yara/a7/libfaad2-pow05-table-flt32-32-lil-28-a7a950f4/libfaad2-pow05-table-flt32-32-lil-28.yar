rule libfaad2_pow05_table__flt32___32_lil_28_ {
  strings:
    $a0 = { fd 44 d7 3f f3 04 b5 3f f0 37 98 3f 00 00 80 3f fd 44 57 3f f3 04 35 3f f0 37 18 3f }

  condition:
    $a0
}