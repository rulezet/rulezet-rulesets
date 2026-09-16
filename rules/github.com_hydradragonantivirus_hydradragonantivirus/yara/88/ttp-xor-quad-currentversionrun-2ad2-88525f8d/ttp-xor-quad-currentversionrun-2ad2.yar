rule TTP_XOR_QUAD_CurrentVersionRun_2ad2 {
  strings:
    $key_2ad2 = { 79 bd [2] 5d b3 [2] 76 9f [2] 58 bd [2] 4c a6 [2] 43 bc [2] 5d a1 [2] 5f a0 [2] 44 a6 [2] 58 a1 [2] 44 8e }

  condition:
    any of them
}