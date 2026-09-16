rule libfaad2_sa_sqrt_1_minus__flt32___32_big_64_ {
  strings:
    $a0 = { 3f 80 00 00 3f 80 00 00 3f 7f ad b3 3f 7b eb cb 3f 7f 5c 78 3f 75 a0 09 3f 7e ba c8 3f 65 09 ff 3f 7d 7b 7f 3f 53 b1 e7 3f 7b 0c c9 3f 34 d0 e8 3f 76 66 10 3e e8 25 e3 3f 6d d7 a2 00 00 00 00 }

  condition:
    $a0
}