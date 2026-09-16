rule TTP_XOR_QUAD_CurrentVersionRun_6dc3 {
  strings:
    $key_6dc3 = { 3e ac [2] 1a a2 [2] 31 8e [2] 1f ac [2] 0b b7 [2] 04 ad [2] 1a b0 [2] 18 b1 [2] 03 b7 [2] 1f b0 [2] 03 9f }

  condition:
    any of them
}