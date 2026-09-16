rule TTP_XOR_QUAD_CurrentVersionRun_23df {
  strings:
    $key_23df = { 70 b0 [2] 54 be [2] 7f 92 [2] 51 b0 [2] 45 ab [2] 4a b1 [2] 54 ac [2] 56 ad [2] 4d ab [2] 51 ac [2] 4d 83 }

  condition:
    any of them
}