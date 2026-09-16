rule TTP_XOR_QUAD_CurrentVersionRun_8edf {
  strings:
    $key_8edf = { dd b0 [2] f9 be [2] d2 92 [2] fc b0 [2] e8 ab [2] e7 b1 [2] f9 ac [2] fb ad [2] e0 ab [2] fc ac [2] e0 83 }

  condition:
    any of them
}