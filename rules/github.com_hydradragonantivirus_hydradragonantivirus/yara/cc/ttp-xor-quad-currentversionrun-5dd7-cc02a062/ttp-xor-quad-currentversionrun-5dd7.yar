rule TTP_XOR_QUAD_CurrentVersionRun_5dd7 {
  strings:
    $key_5dd7 = { 0e b8 [2] 2a b6 [2] 01 9a [2] 2f b8 [2] 3b a3 [2] 34 b9 [2] 2a a4 [2] 28 a5 [2] 33 a3 [2] 2f a4 [2] 33 8b }

  condition:
    any of them
}