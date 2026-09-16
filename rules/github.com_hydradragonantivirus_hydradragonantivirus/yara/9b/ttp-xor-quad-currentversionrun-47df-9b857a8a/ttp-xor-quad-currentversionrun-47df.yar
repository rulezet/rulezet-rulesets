rule TTP_XOR_QUAD_CurrentVersionRun_47df {
  strings:
    $key_47df = { 14 b0 [2] 30 be [2] 1b 92 [2] 35 b0 [2] 21 ab [2] 2e b1 [2] 30 ac [2] 32 ad [2] 29 ab [2] 35 ac [2] 29 83 }

  condition:
    any of them
}