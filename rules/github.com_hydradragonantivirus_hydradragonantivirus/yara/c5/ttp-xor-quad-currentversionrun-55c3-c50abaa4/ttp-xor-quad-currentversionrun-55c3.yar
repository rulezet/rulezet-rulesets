rule TTP_XOR_QUAD_CurrentVersionRun_55c3 {
  strings:
    $key_55c3 = { 06 ac [2] 22 a2 [2] 09 8e [2] 27 ac [2] 33 b7 [2] 3c ad [2] 22 b0 [2] 20 b1 [2] 3b b7 [2] 27 b0 [2] 3b 9f }

  condition:
    any of them
}