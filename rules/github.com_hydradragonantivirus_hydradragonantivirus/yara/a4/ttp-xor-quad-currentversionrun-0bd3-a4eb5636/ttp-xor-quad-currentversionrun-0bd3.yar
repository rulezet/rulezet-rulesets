rule TTP_XOR_QUAD_CurrentVersionRun_0bd3 {
  strings:
    $key_0bd3 = { 58 bc [2] 7c b2 [2] 57 9e [2] 79 bc [2] 6d a7 [2] 62 bd [2] 7c a0 [2] 7e a1 [2] 65 a7 [2] 79 a0 [2] 65 8f }

  condition:
    any of them
}