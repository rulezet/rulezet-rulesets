rule TTP_XOR_QUAD_CurrentVersionRun_1dc3 {
  strings:
    $key_1dc3 = { 4e ac [2] 6a a2 [2] 41 8e [2] 6f ac [2] 7b b7 [2] 74 ad [2] 6a b0 [2] 68 b1 [2] 73 b7 [2] 6f b0 [2] 73 9f }

  condition:
    any of them
}