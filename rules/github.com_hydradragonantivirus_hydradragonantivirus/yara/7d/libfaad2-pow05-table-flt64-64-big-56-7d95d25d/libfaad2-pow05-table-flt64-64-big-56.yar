rule libfaad2_pow05_table__flt64___64_big_56_ {
  strings:
    $a0 = { 3f fa e8 9f 99 5a d3 b1 3f f6 a0 9e 66 7f 3b e3 3f f3 06 fe 0a 31 b7 10 3f f0 00 00 00 00 00 00 3f ea e8 9f 99 5a d3 84 3f e6 a0 9e 66 7f 3b e3 3f e3 06 fe 0a 31 b7 10 }

  condition:
    $a0
}