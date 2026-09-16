rule TTP_XOR_QUAD_CurrentVersionRun_3fdf {
  strings:
    $key_3fdf = { 6c b0 [2] 48 be [2] 63 92 [2] 4d b0 [2] 59 ab [2] 56 b1 [2] 48 ac [2] 4a ad [2] 51 ab [2] 4d ac [2] 51 83 }

  condition:
    any of them
}