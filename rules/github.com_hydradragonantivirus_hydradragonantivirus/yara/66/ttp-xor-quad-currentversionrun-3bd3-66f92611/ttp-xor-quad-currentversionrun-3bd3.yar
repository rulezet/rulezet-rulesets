rule TTP_XOR_QUAD_CurrentVersionRun_3bd3 {
  strings:
    $key_3bd3 = { 68 bc [2] 4c b2 [2] 67 9e [2] 49 bc [2] 5d a7 [2] 52 bd [2] 4c a0 [2] 4e a1 [2] 55 a7 [2] 49 a0 [2] 55 8f }

  condition:
    any of them
}