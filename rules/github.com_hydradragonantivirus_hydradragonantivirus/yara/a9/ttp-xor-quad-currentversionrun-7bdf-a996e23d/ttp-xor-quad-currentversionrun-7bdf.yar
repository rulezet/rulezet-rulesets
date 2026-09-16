rule TTP_XOR_QUAD_CurrentVersionRun_7bdf {
  strings:
    $key_7bdf = { 28 b0 [2] 0c be [2] 27 92 [2] 09 b0 [2] 1d ab [2] 12 b1 [2] 0c ac [2] 0e ad [2] 15 ab [2] 09 ac [2] 15 83 }

  condition:
    any of them
}