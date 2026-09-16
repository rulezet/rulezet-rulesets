rule TTP_XOR_QUAD_CurrentVersionRun_0fdf {
  strings:
    $key_0fdf = { 5c b0 [2] 78 be [2] 53 92 [2] 7d b0 [2] 69 ab [2] 66 b1 [2] 78 ac [2] 7a ad [2] 61 ab [2] 7d ac [2] 61 83 }

  condition:
    any of them
}