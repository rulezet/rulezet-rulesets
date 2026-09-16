rule TTP_XOR_QUAD_CurrentVersionRun_bdd5 {
  strings:
    $key_bdd5 = { ee ba [2] ca b4 [2] e1 98 [2] cf ba [2] db a1 [2] d4 bb [2] ca a6 [2] c8 a7 [2] d3 a1 [2] cf a6 [2] d3 89 }

  condition:
    any of them
}