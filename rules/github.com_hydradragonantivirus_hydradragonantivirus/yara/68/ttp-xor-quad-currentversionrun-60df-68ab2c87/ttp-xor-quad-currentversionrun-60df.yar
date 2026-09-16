rule TTP_XOR_QUAD_CurrentVersionRun_60df {
  strings:
    $key_60df = { 33 b0 [2] 17 be [2] 3c 92 [2] 12 b0 [2] 06 ab [2] 09 b1 [2] 17 ac [2] 15 ad [2] 0e ab [2] 12 ac [2] 0e 83 }

  condition:
    any of them
}