rule TTP_XOR_QUAD_CurrentVersionRun_1fdf {
  strings:
    $key_1fdf = { 4c b0 [2] 68 be [2] 43 92 [2] 6d b0 [2] 79 ab [2] 76 b1 [2] 68 ac [2] 6a ad [2] 71 ab [2] 6d ac [2] 71 83 }

  condition:
    any of them
}