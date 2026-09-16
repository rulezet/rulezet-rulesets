rule TTP_XOR_QUAD_CurrentVersionRun_3bdf {
  strings:
    $key_3bdf = { 68 b0 [2] 4c be [2] 67 92 [2] 49 b0 [2] 5d ab [2] 52 b1 [2] 4c ac [2] 4e ad [2] 55 ab [2] 49 ac [2] 55 83 }

  condition:
    any of them
}