rule TTP_XOR_QUAD_CurrentVersionRun_08d6 {
  strings:
    $key_08d6 = { 5b b9 [2] 7f b7 [2] 54 9b [2] 7a b9 [2] 6e a2 [2] 61 b8 [2] 7f a5 [2] 7d a4 [2] 66 a2 [2] 7a a5 [2] 66 8a }

  condition:
    any of them
}