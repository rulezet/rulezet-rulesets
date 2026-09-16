rule TTP_XOR_QUAD_CurrentVersionRun_2bd3 {
  strings:
    $key_2bd3 = { 78 bc [2] 5c b2 [2] 77 9e [2] 59 bc [2] 4d a7 [2] 42 bd [2] 5c a0 [2] 5e a1 [2] 45 a7 [2] 59 a0 [2] 45 8f }

  condition:
    any of them
}