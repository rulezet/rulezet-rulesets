rule TTP_XOR_QUAD_CurrentVersionRun_28c6 {
  strings:
    $key_28c6 = { 7b a9 [2] 5f a7 [2] 74 8b [2] 5a a9 [2] 4e b2 [2] 41 a8 [2] 5f b5 [2] 5d b4 [2] 46 b2 [2] 5a b5 [2] 46 9a }

  condition:
    any of them
}