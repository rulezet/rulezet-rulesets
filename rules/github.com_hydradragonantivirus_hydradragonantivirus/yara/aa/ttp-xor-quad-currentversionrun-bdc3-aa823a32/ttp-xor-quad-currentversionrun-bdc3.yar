rule TTP_XOR_QUAD_CurrentVersionRun_bdc3 {
  strings:
    $key_bdc3 = { ee ac [2] ca a2 [2] e1 8e [2] cf ac [2] db b7 [2] d4 ad [2] ca b0 [2] c8 b1 [2] d3 b7 [2] cf b0 [2] d3 9f }

  condition:
    any of them
}