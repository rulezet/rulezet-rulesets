rule TTP_XOR_QUAD_CurrentVersionRun_5fdf {
  strings:
    $key_5fdf = { 0c b0 [2] 28 be [2] 03 92 [2] 2d b0 [2] 39 ab [2] 36 b1 [2] 28 ac [2] 2a ad [2] 31 ab [2] 2d ac [2] 31 83 }

  condition:
    any of them
}