rule TTP_XOR_QUAD_CurrentVersionRun_69d6 {
  strings:
    $key_69d6 = { 3a b9 [2] 1e b7 [2] 35 9b [2] 1b b9 [2] 0f a2 [2] 00 b8 [2] 1e a5 [2] 1c a4 [2] 07 a2 [2] 1b a5 [2] 07 8a }

  condition:
    any of them
}