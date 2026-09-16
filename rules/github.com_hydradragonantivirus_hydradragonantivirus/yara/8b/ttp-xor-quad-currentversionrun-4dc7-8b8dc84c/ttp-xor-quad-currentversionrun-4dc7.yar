rule TTP_XOR_QUAD_CurrentVersionRun_4dc7 {
  strings:
    $key_4dc7 = { 1e a8 [2] 3a a6 [2] 11 8a [2] 3f a8 [2] 2b b3 [2] 24 a9 [2] 3a b4 [2] 38 b5 [2] 23 b3 [2] 3f b4 [2] 23 9b }

  condition:
    any of them
}