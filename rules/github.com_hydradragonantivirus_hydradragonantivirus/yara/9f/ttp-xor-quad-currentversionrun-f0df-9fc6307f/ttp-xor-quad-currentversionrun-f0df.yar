rule TTP_XOR_QUAD_CurrentVersionRun_f0df {
  strings:
    $key_f0df = { a3 b0 [2] 87 be [2] ac 92 [2] 82 b0 [2] 96 ab [2] 99 b1 [2] 87 ac [2] 85 ad [2] 9e ab [2] 82 ac [2] 9e 83 }

  condition:
    any of them
}