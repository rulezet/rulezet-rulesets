rule TTP_XOR_QUAD_CurrentVersionRun_5dd3 {
  strings:
    $key_5dd3 = { 0e bc [2] 2a b2 [2] 01 9e [2] 2f bc [2] 3b a7 [2] 34 bd [2] 2a a0 [2] 28 a1 [2] 33 a7 [2] 2f a0 [2] 33 8f }

  condition:
    any of them
}