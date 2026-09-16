rule TTP_XOR_QUAD_CurrentVersionRun_99d6 {
  strings:
    $key_99d6 = { ca b9 [2] ee b7 [2] c5 9b [2] eb b9 [2] ff a2 [2] f0 b8 [2] ee a5 [2] ec a4 [2] f7 a2 [2] eb a5 [2] f7 8a }

  condition:
    any of them
}