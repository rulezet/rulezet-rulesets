rule TTP_XOR_QUAD_CurrentVersionRun_79d7 {
  strings:
    $key_79d7 = { 2a b8 [2] 0e b6 [2] 25 9a [2] 0b b8 [2] 1f a3 [2] 10 b9 [2] 0e a4 [2] 0c a5 [2] 17 a3 [2] 0b a4 [2] 17 8b }

  condition:
    any of them
}