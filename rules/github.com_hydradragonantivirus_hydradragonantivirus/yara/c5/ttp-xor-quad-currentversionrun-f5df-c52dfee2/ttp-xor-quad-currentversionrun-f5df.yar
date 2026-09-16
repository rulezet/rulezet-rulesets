rule TTP_XOR_QUAD_CurrentVersionRun_f5df {
  strings:
    $key_f5df = { a6 b0 [2] 82 be [2] a9 92 [2] 87 b0 [2] 93 ab [2] 9c b1 [2] 82 ac [2] 80 ad [2] 9b ab [2] 87 ac [2] 9b 83 }

  condition:
    any of them
}