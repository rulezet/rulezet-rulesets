rule TTP_XOR_QUAD_CurrentVersionRun_78c7 {
  strings:
    $key_78c7 = { 2b a8 [2] 0f a6 [2] 24 8a [2] 0a a8 [2] 1e b3 [2] 11 a9 [2] 0f b4 [2] 0d b5 [2] 16 b3 [2] 0a b4 [2] 16 9b }

  condition:
    any of them
}