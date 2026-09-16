rule TTP_XOR_QUAD_CurrentVersionRun_3ad3 {
  strings:
    $key_3ad3 = { 69 bc [2] 4d b2 [2] 66 9e [2] 48 bc [2] 5c a7 [2] 53 bd [2] 4d a0 [2] 4f a1 [2] 54 a7 [2] 48 a0 [2] 54 8f }

  condition:
    any of them
}