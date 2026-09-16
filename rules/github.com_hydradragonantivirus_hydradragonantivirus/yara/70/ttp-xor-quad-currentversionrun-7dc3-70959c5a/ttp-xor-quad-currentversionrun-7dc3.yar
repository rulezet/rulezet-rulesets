rule TTP_XOR_QUAD_CurrentVersionRun_7dc3 {
  strings:
    $key_7dc3 = { 2e ac [2] 0a a2 [2] 21 8e [2] 0f ac [2] 1b b7 [2] 14 ad [2] 0a b0 [2] 08 b1 [2] 13 b7 [2] 0f b0 [2] 13 9f }

  condition:
    any of them
}