rule TTP_XOR_QUAD_CurrentVersionRun_54c3 {
  strings:
    $key_54c3 = { 07 ac [2] 23 a2 [2] 08 8e [2] 26 ac [2] 32 b7 [2] 3d ad [2] 23 b0 [2] 21 b1 [2] 3a b7 [2] 26 b0 [2] 3a 9f }

  condition:
    any of them
}