rule TTP_XOR_QUAD_CurrentVersionRun_4fdf {
  strings:
    $key_4fdf = { 1c b0 [2] 38 be [2] 13 92 [2] 3d b0 [2] 29 ab [2] 26 b1 [2] 38 ac [2] 3a ad [2] 21 ab [2] 3d ac [2] 21 83 }

  condition:
    any of them
}