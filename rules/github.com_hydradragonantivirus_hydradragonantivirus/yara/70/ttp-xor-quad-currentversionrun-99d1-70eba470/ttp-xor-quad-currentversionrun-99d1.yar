rule TTP_XOR_QUAD_CurrentVersionRun_99d1 {
  strings:
    $key_99d1 = { ca be [2] ee b0 [2] c5 9c [2] eb be [2] ff a5 [2] f0 bf [2] ee a2 [2] ec a3 [2] f7 a5 [2] eb a2 [2] f7 8d }

  condition:
    any of them
}