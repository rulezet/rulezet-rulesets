rule TTP_XOR_QUAD_CurrentVersionRun_bdc7 {
  strings:
    $key_bdc7 = { ee a8 [2] ca a6 [2] e1 8a [2] cf a8 [2] db b3 [2] d4 a9 [2] ca b4 [2] c8 b5 [2] d3 b3 [2] cf b4 [2] d3 9b }

  condition:
    any of them
}