rule TTP_XOR_QUAD_CurrentVersionRun_3dc3 {
  strings:
    $key_3dc3 = { 6e ac [2] 4a a2 [2] 61 8e [2] 4f ac [2] 5b b7 [2] 54 ad [2] 4a b0 [2] 48 b1 [2] 53 b7 [2] 4f b0 [2] 53 9f }

  condition:
    any of them
}