rule TTP_XOR_QUAD_CurrentVersionRun_7ad3 {
  strings:
    $key_7ad3 = { 29 bc [2] 0d b2 [2] 26 9e [2] 08 bc [2] 1c a7 [2] 13 bd [2] 0d a0 [2] 0f a1 [2] 14 a7 [2] 08 a0 [2] 14 8f }

  condition:
    any of them
}