rule TTP_XOR_QUAD_CurrentVersionRun_bdce {
  strings:
    $key_bdce = { ee a1 [2] ca af [2] e1 83 [2] cf a1 [2] db ba [2] d4 a0 [2] ca bd [2] c8 bc [2] d3 ba [2] cf bd [2] d3 92 }

  condition:
    any of them
}