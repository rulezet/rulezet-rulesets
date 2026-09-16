rule libfaad2_sa_sqrt_1_minus__flt64___64_lil_128_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 14 dd ba 68 b6 f5 ef 3f 2d 10 a2 54 79 7d ef 3f 58 79 c5 fd 8e eb ef 3f 6b 62 be 12 01 b4 ee 3f 3e 9c 62 03 59 d7 ef 3f a4 1b ce ed 3f a1 ec 3f bb a7 1a d9 6f af ef 3f 10 9c 0f dc 3c 76 ea 3f 05 b4 93 12 99 61 ef 3f 27 b1 5f 08 1d 9a e6 3f 55 0b 66 f8 c1 cc ee 3f ff c7 cf 67 bc 04 dd 3f d0 24 3f 4f f4 ba ed 3f 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}