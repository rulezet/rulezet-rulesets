rule TTP_XOR_QUAD_CurrentVersionRun_7edf {
  strings:
    $key_7edf = { 2d b0 [2] 09 be [2] 22 92 [2] 0c b0 [2] 18 ab [2] 17 b1 [2] 09 ac [2] 0b ad [2] 10 ab [2] 0c ac [2] 10 83 }

  condition:
    any of them
}