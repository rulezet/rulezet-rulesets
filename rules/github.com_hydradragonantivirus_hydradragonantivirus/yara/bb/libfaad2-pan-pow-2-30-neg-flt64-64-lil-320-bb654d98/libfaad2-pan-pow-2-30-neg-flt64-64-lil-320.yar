rule libfaad2_pan_pow_2_30_neg__flt64___64_lil_320_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f0 3f 1a ca c3 21 9f e0 ef 3f 1a ca c3 21 9f e0 ef 3f 1e 77 f6 07 5d c1 ef 3f 1e 77 f6 07 5d c1 ef 3f bf 06 6d 07 5d c1 ef 3f 1e 77 f6 07 5d c1 ef 3f 1e 77 f6 07 5d c1 ef 3f aa 77 02 ab 34 83 ef 3f 25 31 31 2b 4e 64 ef 3f 25 31 31 2b 4e 64 ef 3f 95 e2 10 95 39 a2 ef 3f aa 77 02 ab 34 83 ef 3f f1 5a 9f f8 85 45 ef 3f 92 8a d3 04 e2 e9 ee 3f 1b d7 48 dd 91 cb ee 3f aa 77 02 ab 34 83 ef 3f f1 5a 9f f8 85 45 ef 3f 92 8a d3 04 e2 e9 ee 3f 82 67 45 4b 53 71 ee 3f a3 72 09 43 c1 35 ee 3f 25 31 31 2b 4e 64 ef 3f 1f ac f7 02 50 08 ef 3f 82 67 45 4b 53 71 ee 3f fa b9 43 b8 39 dd ed 3f f0 2e a5 9b b5 85 ed 3f f1 5a 9f f8 85 45 ef 3f a0 dd 59 6f 5f ad ee 3f c0 62 72 42 9f fa ed 3f 75 52 76 32 ec 4b ed 3f b0 34 9a a3 61 bd ec 3f 1f ac f7 02 50 08 ef 3f 31 61 5a f2 7d 53 ee 3f f0 2e a5 9b b5 85 ed 3f b0 34 9a a3 61 bd ec 3f 12 eb 73 06 5d fa eb 3f }

  condition:
    $a0
}