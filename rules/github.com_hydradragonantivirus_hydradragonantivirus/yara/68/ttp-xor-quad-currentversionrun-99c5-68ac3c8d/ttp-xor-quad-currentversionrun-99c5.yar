rule TTP_XOR_QUAD_CurrentVersionRun_99c5 {
  strings:
    $key_99c5 = { ca aa [2] ee a4 [2] c5 88 [2] eb aa [2] ff b1 [2] f0 ab [2] ee b6 [2] ec b7 [2] f7 b1 [2] eb b6 [2] f7 99 }

  condition:
    any of them
}