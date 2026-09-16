rule TTP_XOR_QUAD_CurrentVersionRun_99c3 {
  strings:
    $key_99c3 = { ca ac [2] ee a2 [2] c5 8e [2] eb ac [2] ff b7 [2] f0 ad [2] ee b0 [2] ec b1 [2] f7 b7 [2] eb b0 [2] f7 9f }

  condition:
    any of them
}