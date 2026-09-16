rule TTP_XOR_QUAD_CurrentVersionRun_3edf {
  strings:
    $key_3edf = { 6d b0 [2] 49 be [2] 62 92 [2] 4c b0 [2] 58 ab [2] 57 b1 [2] 49 ac [2] 4b ad [2] 50 ab [2] 4c ac [2] 50 83 }

  condition:
    any of them
}