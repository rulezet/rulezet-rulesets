rule TTP_XOR_QUAD_CurrentVersionRun_5ad3 {
  strings:
    $key_5ad3 = { 09 bc [2] 2d b2 [2] 06 9e [2] 28 bc [2] 3c a7 [2] 33 bd [2] 2d a0 [2] 2f a1 [2] 34 a7 [2] 28 a0 [2] 34 8f }

  condition:
    any of them
}