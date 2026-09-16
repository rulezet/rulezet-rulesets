rule TTP_XOR_QUAD_CurrentVersionRun_99c4 {
  strings:
    $key_99c4 = { ca ab [2] ee a5 [2] c5 89 [2] eb ab [2] ff b0 [2] f0 aa [2] ee b7 [2] ec b6 [2] f7 b0 [2] eb b7 [2] f7 98 }

  condition:
    any of them
}