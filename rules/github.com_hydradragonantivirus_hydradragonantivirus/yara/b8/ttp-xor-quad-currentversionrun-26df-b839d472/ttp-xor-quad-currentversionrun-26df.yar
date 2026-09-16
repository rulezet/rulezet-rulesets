rule TTP_XOR_QUAD_CurrentVersionRun_26df {
  strings:
    $key_26df = { 75 b0 [2] 51 be [2] 7a 92 [2] 54 b0 [2] 40 ab [2] 4f b1 [2] 51 ac [2] 53 ad [2] 48 ab [2] 54 ac [2] 48 83 }

  condition:
    any of them
}