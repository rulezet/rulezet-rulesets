rule TTP_XOR_QUAD_CurrentVersionRun_0edf {
  strings:
    $key_0edf = { 5d b0 [2] 79 be [2] 52 92 [2] 7c b0 [2] 68 ab [2] 67 b1 [2] 79 ac [2] 7b ad [2] 60 ab [2] 7c ac [2] 60 83 }

  condition:
    any of them
}