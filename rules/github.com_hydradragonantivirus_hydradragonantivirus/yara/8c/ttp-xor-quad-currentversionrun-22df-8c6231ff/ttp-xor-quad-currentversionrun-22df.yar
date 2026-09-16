rule TTP_XOR_QUAD_CurrentVersionRun_22df {
  strings:
    $key_22df = { 71 b0 [2] 55 be [2] 7e 92 [2] 50 b0 [2] 44 ab [2] 4b b1 [2] 55 ac [2] 57 ad [2] 4c ab [2] 50 ac [2] 4c 83 }

  condition:
    any of them
}