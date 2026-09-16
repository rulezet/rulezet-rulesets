rule TTP_XOR_QUAD_CurrentVersionRun_64df {
  strings:
    $key_64df = { 37 b0 [2] 13 be [2] 38 92 [2] 16 b0 [2] 02 ab [2] 0d b1 [2] 13 ac [2] 11 ad [2] 0a ab [2] 16 ac [2] 0a 83 }

  condition:
    any of them
}