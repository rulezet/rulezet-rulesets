rule TTP_XOR_QUAD_CurrentVersionRun_7adf {
  strings:
    $key_7adf = { 29 b0 [2] 0d be [2] 26 92 [2] 08 b0 [2] 1c ab [2] 13 b1 [2] 0d ac [2] 0f ad [2] 14 ab [2] 08 ac [2] 14 83 }

  condition:
    any of them
}