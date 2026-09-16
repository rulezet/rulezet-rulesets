rule TTP_XOR_QUAD_CurrentVersionRun_bdc9 {
  strings:
    $key_bdc9 = { ee a6 [2] ca a8 [2] e1 84 [2] cf a6 [2] db bd [2] d4 a7 [2] ca ba [2] c8 bb [2] d3 bd [2] cf ba [2] d3 95 }

  condition:
    any of them
}