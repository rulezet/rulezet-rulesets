rule TTP_XOR_QUAD_CurrentVersionRun_28c7 {
  strings:
    $key_28c7 = { 7b a8 [2] 5f a6 [2] 74 8a [2] 5a a8 [2] 4e b3 [2] 41 a9 [2] 5f b4 [2] 5d b5 [2] 46 b3 [2] 5a b4 [2] 46 9b }

  condition:
    any of them
}