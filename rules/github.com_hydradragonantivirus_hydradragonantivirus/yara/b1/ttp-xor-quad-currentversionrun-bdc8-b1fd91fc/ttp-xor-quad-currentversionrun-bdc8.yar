rule TTP_XOR_QUAD_CurrentVersionRun_bdc8 {
  strings:
    $key_bdc8 = { ee a7 [2] ca a9 [2] e1 85 [2] cf a7 [2] db bc [2] d4 a6 [2] ca bb [2] c8 ba [2] d3 bc [2] cf bb [2] d3 94 }

  condition:
    any of them
}