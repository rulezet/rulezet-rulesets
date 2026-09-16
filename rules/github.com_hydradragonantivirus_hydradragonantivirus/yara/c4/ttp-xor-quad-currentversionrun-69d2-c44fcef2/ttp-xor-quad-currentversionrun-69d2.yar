rule TTP_XOR_QUAD_CurrentVersionRun_69d2 {
  strings:
    $key_69d2 = { 3a bd [2] 1e b3 [2] 35 9f [2] 1b bd [2] 0f a6 [2] 00 bc [2] 1e a1 [2] 1c a0 [2] 07 a6 [2] 1b a1 [2] 07 8e }

  condition:
    any of them
}