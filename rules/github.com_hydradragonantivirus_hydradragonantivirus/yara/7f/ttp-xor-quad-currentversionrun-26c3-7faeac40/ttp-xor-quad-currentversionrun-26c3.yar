rule TTP_XOR_QUAD_CurrentVersionRun_26c3 {
  strings:
    $key_26c3 = { 75 ac [2] 51 a2 [2] 7a 8e [2] 54 ac [2] 40 b7 [2] 4f ad [2] 51 b0 [2] 53 b1 [2] 48 b7 [2] 54 b0 [2] 48 9f }

  condition:
    any of them
}