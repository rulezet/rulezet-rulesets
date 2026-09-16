rule TTP_XOR_QUAD_CurrentVersionRun_5bdf {
  strings:
    $key_5bdf = { 08 b0 [2] 2c be [2] 07 92 [2] 29 b0 [2] 3d ab [2] 32 b1 [2] 2c ac [2] 2e ad [2] 35 ab [2] 29 ac [2] 35 83 }

  condition:
    any of them
}