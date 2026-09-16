rule TTP_XOR_QUAD_CurrentVersionRun_ecc3 {
  strings:
    $key_ecc3 = { bf ac [2] 9b a2 [2] b0 8e [2] 9e ac [2] 8a b7 [2] 85 ad [2] 9b b0 [2] 99 b1 [2] 82 b7 [2] 9e b0 [2] 82 9f }

  condition:
    any of them
}