rule TTP_XOR_QUAD_CurrentVersionRun_48d6 {
  strings:
    $key_48d6 = { 1b b9 [2] 3f b7 [2] 14 9b [2] 3a b9 [2] 2e a2 [2] 21 b8 [2] 3f a5 [2] 3d a4 [2] 26 a2 [2] 3a a5 [2] 26 8a }

  condition:
    any of them
}