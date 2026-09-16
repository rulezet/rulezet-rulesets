rule TTP_XOR_QUAD_CurrentVersionRun_99d4 {
  strings:
    $key_99d4 = { ca bb [2] ee b5 [2] c5 99 [2] eb bb [2] ff a0 [2] f0 ba [2] ee a7 [2] ec a6 [2] f7 a0 [2] eb a7 [2] f7 88 }

  condition:
    any of them
}