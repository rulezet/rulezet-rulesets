rule TTP_XOR_QUAD_CurrentVersionRun_38c6 {
  strings:
    $key_38c6 = { 6b a9 [2] 4f a7 [2] 64 8b [2] 4a a9 [2] 5e b2 [2] 51 a8 [2] 4f b5 [2] 4d b4 [2] 56 b2 [2] 4a b5 [2] 56 9a }

  condition:
    any of them
}