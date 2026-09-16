rule TTP_XOR_QUAD_CurrentVersionRun_50df {
  strings:
    $key_50df = { 03 b0 [2] 27 be [2] 0c 92 [2] 22 b0 [2] 36 ab [2] 39 b1 [2] 27 ac [2] 25 ad [2] 3e ab [2] 22 ac [2] 3e 83 }

  condition:
    any of them
}