rule libfaad2_pow05_table__flt64___64_lil_56_ {
  strings:
    $a0 = { b1 d3 5a 99 9f e8 fa 3f e3 3b 7f 66 9e a0 f6 3f 10 b7 31 0a fe 06 f3 3f 00 00 00 00 00 00 f0 3f 84 d3 5a 99 9f e8 ea 3f e3 3b 7f 66 9e a0 e6 3f 10 b7 31 0a fe 06 e3 3f }

  condition:
    $a0
}