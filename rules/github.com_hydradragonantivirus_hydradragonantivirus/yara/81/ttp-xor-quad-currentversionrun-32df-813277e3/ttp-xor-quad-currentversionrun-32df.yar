rule TTP_XOR_QUAD_CurrentVersionRun_32df {
  strings:
    $key_32df = { 61 b0 [2] 45 be [2] 6e 92 [2] 40 b0 [2] 54 ab [2] 5b b1 [2] 45 ac [2] 47 ad [2] 5c ab [2] 40 ac [2] 5c 83 }

  condition:
    any of them
}