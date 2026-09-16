rule TTP_XOR_QUAD_CurrentVersionRun_fed3 {
  strings:
    $key_fed3 = { ad bc [2] 89 b2 [2] a2 9e [2] 8c bc [2] 98 a7 [2] 97 bd [2] 89 a0 [2] 8b a1 [2] 90 a7 [2] 8c a0 [2] 90 8f }

  condition:
    any of them
}