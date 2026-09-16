rule TTP_XOR_QUAD_CurrentVersionRun_f6df {
  strings:
    $key_f6df = { a5 b0 [2] 81 be [2] aa 92 [2] 84 b0 [2] 90 ab [2] 9f b1 [2] 81 ac [2] 83 ad [2] 98 ab [2] 84 ac [2] 98 83 }

  condition:
    any of them
}