rule TTP_XOR_QUAD_CurrentVersionRun_3adf {
  strings:
    $key_3adf = { 69 b0 [2] 4d be [2] 66 92 [2] 48 b0 [2] 5c ab [2] 53 b1 [2] 4d ac [2] 4f ad [2] 54 ab [2] 48 ac [2] 54 83 }

  condition:
    any of them
}