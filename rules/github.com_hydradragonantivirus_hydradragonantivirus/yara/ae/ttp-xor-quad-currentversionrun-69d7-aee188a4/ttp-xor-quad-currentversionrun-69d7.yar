rule TTP_XOR_QUAD_CurrentVersionRun_69d7 {
  strings:
    $key_69d7 = { 3a b8 [2] 1e b6 [2] 35 9a [2] 1b b8 [2] 0f a3 [2] 00 b9 [2] 1e a4 [2] 1c a5 [2] 07 a3 [2] 1b a4 [2] 07 8b }

  condition:
    any of them
}