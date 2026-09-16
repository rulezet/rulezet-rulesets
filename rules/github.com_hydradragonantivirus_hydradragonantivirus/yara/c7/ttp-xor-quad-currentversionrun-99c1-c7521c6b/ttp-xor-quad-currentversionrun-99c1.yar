rule TTP_XOR_QUAD_CurrentVersionRun_99c1 {
  strings:
    $key_99c1 = { ca ae [2] ee a0 [2] c5 8c [2] eb ae [2] ff b5 [2] f0 af [2] ee b2 [2] ec b3 [2] f7 b5 [2] eb b2 [2] f7 9d }

  condition:
    any of them
}