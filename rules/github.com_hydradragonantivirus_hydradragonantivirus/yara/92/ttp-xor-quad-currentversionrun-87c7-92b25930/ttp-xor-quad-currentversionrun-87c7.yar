rule TTP_XOR_QUAD_CurrentVersionRun_87c7 {
  strings:
    $key_87c7 = { d4 a8 [2] f0 a6 [2] db 8a [2] f5 a8 [2] e1 b3 [2] ee a9 [2] f0 b4 [2] f2 b5 [2] e9 b3 [2] f5 b4 [2] e9 9b }

  condition:
    any of them
}