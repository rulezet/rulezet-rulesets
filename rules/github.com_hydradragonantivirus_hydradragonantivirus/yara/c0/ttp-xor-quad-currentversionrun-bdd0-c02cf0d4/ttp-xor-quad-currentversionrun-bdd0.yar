rule TTP_XOR_QUAD_CurrentVersionRun_bdd0 {
  strings:
    $key_bdd0 = { ee bf [2] ca b1 [2] e1 9d [2] cf bf [2] db a4 [2] d4 be [2] ca a3 [2] c8 a2 [2] d3 a4 [2] cf a3 [2] d3 8c }

  condition:
    any of them
}