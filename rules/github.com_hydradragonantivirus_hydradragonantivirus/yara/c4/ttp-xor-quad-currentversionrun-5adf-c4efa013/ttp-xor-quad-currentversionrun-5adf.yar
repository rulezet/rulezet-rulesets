rule TTP_XOR_QUAD_CurrentVersionRun_5adf {
  strings:
    $key_5adf = { 09 b0 [2] 2d be [2] 06 92 [2] 28 b0 [2] 3c ab [2] 33 b1 [2] 2d ac [2] 2f ad [2] 34 ab [2] 28 ac [2] 34 83 }

  condition:
    any of them
}