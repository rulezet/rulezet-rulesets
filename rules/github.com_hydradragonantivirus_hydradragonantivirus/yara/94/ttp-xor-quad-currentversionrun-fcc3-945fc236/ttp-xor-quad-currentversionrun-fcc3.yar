rule TTP_XOR_QUAD_CurrentVersionRun_fcc3 {
  strings:
    $key_fcc3 = { af ac [2] 8b a2 [2] a0 8e [2] 8e ac [2] 9a b7 [2] 95 ad [2] 8b b0 [2] 89 b1 [2] 92 b7 [2] 8e b0 [2] 92 9f }

  condition:
    any of them
}