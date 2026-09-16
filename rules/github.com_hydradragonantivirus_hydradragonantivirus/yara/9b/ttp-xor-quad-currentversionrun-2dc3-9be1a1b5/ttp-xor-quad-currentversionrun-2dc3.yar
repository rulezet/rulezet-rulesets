rule TTP_XOR_QUAD_CurrentVersionRun_2dc3 {
  strings:
    $key_2dc3 = { 7e ac [2] 5a a2 [2] 71 8e [2] 5f ac [2] 4b b7 [2] 44 ad [2] 5a b0 [2] 58 b1 [2] 43 b7 [2] 5f b0 [2] 43 9f }

  condition:
    any of them
}