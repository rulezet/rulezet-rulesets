rule TTP_XOR_QUAD_CurrentVersionRun_46c3 {
  strings:
    $key_46c3 = { 15 ac [2] 31 a2 [2] 1a 8e [2] 34 ac [2] 20 b7 [2] 2f ad [2] 31 b0 [2] 33 b1 [2] 28 b7 [2] 34 b0 [2] 28 9f }

  condition:
    any of them
}