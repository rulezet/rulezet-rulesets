rule TTP_XOR_QUAD_CurrentVersionRun_8ddf {
  strings:
    $key_8ddf = { de b0 [2] fa be [2] d1 92 [2] ff b0 [2] eb ab [2] e4 b1 [2] fa ac [2] f8 ad [2] e3 ab [2] ff ac [2] e3 83 }

  condition:
    any of them
}