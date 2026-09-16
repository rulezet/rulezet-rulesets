rule TTP_XOR_QUAD_CurrentVersionRun_2dd3 {
  strings:
    $key_2dd3 = { 7e bc [2] 5a b2 [2] 71 9e [2] 5f bc [2] 4b a7 [2] 44 bd [2] 5a a0 [2] 58 a1 [2] 43 a7 [2] 5f a0 [2] 43 8f }

  condition:
    any of them
}