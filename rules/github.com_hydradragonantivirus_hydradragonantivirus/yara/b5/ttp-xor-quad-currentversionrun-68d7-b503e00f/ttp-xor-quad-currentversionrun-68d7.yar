rule TTP_XOR_QUAD_CurrentVersionRun_68d7 {
  strings:
    $key_68d7 = { 3b b8 [2] 1f b6 [2] 34 9a [2] 1a b8 [2] 0e a3 [2] 01 b9 [2] 1f a4 [2] 1d a5 [2] 06 a3 [2] 1a a4 [2] 06 8b }

  condition:
    any of them
}