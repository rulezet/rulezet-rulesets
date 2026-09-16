rule TTP_XOR_QUAD_CurrentVersionRun_2dc7 {
  strings:
    $key_2dc7 = { 7e a8 [2] 5a a6 [2] 71 8a [2] 5f a8 [2] 4b b3 [2] 44 a9 [2] 5a b4 [2] 58 b5 [2] 43 b3 [2] 5f b4 [2] 43 9b }

  condition:
    any of them
}