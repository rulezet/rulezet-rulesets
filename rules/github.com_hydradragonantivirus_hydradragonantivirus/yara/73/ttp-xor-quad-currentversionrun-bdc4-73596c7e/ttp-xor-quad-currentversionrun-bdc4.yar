rule TTP_XOR_QUAD_CurrentVersionRun_bdc4 {
  strings:
    $key_bdc4 = { ee ab [2] ca a5 [2] e1 89 [2] cf ab [2] db b0 [2] d4 aa [2] ca b7 [2] c8 b6 [2] d3 b0 [2] cf b7 [2] d3 98 }

  condition:
    any of them
}