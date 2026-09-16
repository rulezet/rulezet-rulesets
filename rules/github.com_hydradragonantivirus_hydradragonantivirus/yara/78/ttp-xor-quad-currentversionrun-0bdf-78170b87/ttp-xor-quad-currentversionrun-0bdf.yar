rule TTP_XOR_QUAD_CurrentVersionRun_0bdf {
  strings:
    $key_0bdf = { 58 b0 [2] 7c be [2] 57 92 [2] 79 b0 [2] 6d ab [2] 62 b1 [2] 7c ac [2] 7e ad [2] 65 ab [2] 79 ac [2] 65 83 }

  condition:
    any of them
}