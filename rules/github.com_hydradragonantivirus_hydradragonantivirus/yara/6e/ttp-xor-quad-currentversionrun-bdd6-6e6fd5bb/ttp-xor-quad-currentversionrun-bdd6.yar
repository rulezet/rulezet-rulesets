rule TTP_XOR_QUAD_CurrentVersionRun_bdd6 {
  strings:
    $key_bdd6 = { ee b9 [2] ca b7 [2] e1 9b [2] cf b9 [2] db a2 [2] d4 b8 [2] ca a5 [2] c8 a4 [2] d3 a2 [2] cf a5 [2] d3 8a }

  condition:
    any of them
}