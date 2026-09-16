rule TTP_XOR_QUAD_CurrentVersionRun_bdc2 {
  strings:
    $key_bdc2 = { ee ad [2] ca a3 [2] e1 8f [2] cf ad [2] db b6 [2] d4 ac [2] ca b1 [2] c8 b0 [2] d3 b6 [2] cf b1 [2] d3 9e }

  condition:
    any of them
}