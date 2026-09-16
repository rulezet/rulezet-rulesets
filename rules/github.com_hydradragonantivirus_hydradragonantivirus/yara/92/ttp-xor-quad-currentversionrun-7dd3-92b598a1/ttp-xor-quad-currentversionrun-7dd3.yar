rule TTP_XOR_QUAD_CurrentVersionRun_7dd3 {
  strings:
    $key_7dd3 = { 2e bc [2] 0a b2 [2] 21 9e [2] 0f bc [2] 1b a7 [2] 14 bd [2] 0a a0 [2] 08 a1 [2] 13 a7 [2] 0f a0 [2] 13 8f }

  condition:
    any of them
}