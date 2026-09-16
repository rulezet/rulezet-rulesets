rule TTP_XOR_QUAD_CurrentVersionRun_56c3 {
  strings:
    $key_56c3 = { 05 ac [2] 21 a2 [2] 0a 8e [2] 24 ac [2] 30 b7 [2] 3f ad [2] 21 b0 [2] 23 b1 [2] 38 b7 [2] 24 b0 [2] 38 9f }

  condition:
    any of them
}