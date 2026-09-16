rule TTP_XOR_QUAD_CurrentVersionRun_46df {
  strings:
    $key_46df = { 15 b0 [2] 31 be [2] 1a 92 [2] 34 b0 [2] 20 ab [2] 2f b1 [2] 31 ac [2] 33 ad [2] 28 ab [2] 34 ac [2] 28 83 }

  condition:
    any of them
}