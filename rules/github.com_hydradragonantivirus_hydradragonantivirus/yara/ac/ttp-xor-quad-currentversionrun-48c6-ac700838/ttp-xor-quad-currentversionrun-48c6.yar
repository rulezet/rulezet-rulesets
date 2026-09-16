rule TTP_XOR_QUAD_CurrentVersionRun_48c6 {
  strings:
    $key_48c6 = { 1b a9 [2] 3f a7 [2] 14 8b [2] 3a a9 [2] 2e b2 [2] 21 a8 [2] 3f b5 [2] 3d b4 [2] 26 b2 [2] 3a b5 [2] 26 9a }

  condition:
    any of them
}