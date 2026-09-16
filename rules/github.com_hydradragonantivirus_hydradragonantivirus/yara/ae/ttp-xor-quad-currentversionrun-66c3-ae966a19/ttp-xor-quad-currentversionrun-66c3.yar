rule TTP_XOR_QUAD_CurrentVersionRun_66c3 {
  strings:
    $key_66c3 = { 35 ac [2] 11 a2 [2] 3a 8e [2] 14 ac [2] 00 b7 [2] 0f ad [2] 11 b0 [2] 13 b1 [2] 08 b7 [2] 14 b0 [2] 08 9f }

  condition:
    any of them
}