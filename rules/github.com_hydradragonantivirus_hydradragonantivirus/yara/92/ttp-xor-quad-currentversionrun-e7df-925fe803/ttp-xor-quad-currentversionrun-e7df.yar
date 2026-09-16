rule TTP_XOR_QUAD_CurrentVersionRun_e7df {
  strings:
    $key_e7df = { b4 b0 [2] 90 be [2] bb 92 [2] 95 b0 [2] 81 ab [2] 8e b1 [2] 90 ac [2] 92 ad [2] 89 ab [2] 95 ac [2] 89 83 }

  condition:
    any of them
}