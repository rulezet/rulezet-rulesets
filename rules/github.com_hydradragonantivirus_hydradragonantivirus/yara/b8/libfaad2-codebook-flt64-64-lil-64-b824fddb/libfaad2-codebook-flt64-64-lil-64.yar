rule libfaad2_codebook__flt64___64_lil_64_ {
  strings:
    $a0 = { e2 77 d3 2d 3b 44 e2 3f cb d9 3b a3 ad 4a e6 3f c5 8c f0 f6 20 04 ea 3f f5 d8 96 01 67 29 ed 3f a3 92 3a 01 4d 84 ef 3f 94 83 d9 04 18 16 f1 3f 66 4d 2c f0 15 1d f3 3f 2d af 5c 6f 9b e9 f5 3f }

  condition:
    $a0
}