rule TTP_XOR_QUAD_CurrentVersionRun_7bd3 {
  strings:
    $key_7bd3 = { 28 bc [2] 0c b2 [2] 27 9e [2] 09 bc [2] 1d a7 [2] 12 bd [2] 0c a0 [2] 0e a1 [2] 15 a7 [2] 09 a0 [2] 15 8f }

  condition:
    any of them
}