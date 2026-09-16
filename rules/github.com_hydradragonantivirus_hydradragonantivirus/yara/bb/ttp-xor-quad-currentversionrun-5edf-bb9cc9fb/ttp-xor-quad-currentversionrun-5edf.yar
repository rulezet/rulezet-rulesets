rule TTP_XOR_QUAD_CurrentVersionRun_5edf {
  strings:
    $key_5edf = { 0d b0 [2] 29 be [2] 02 92 [2] 2c b0 [2] 38 ab [2] 37 b1 [2] 29 ac [2] 2b ad [2] 30 ab [2] 2c ac [2] 30 83 }

  condition:
    any of them
}