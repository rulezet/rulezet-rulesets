rule TTP_XOR_QUAD_CurrentVersionRun_bdca {
  strings:
    $key_bdca = { ee a5 [2] ca ab [2] e1 87 [2] cf a5 [2] db be [2] d4 a4 [2] ca b9 [2] c8 b8 [2] d3 be [2] cf b9 [2] d3 96 }

  condition:
    any of them
}