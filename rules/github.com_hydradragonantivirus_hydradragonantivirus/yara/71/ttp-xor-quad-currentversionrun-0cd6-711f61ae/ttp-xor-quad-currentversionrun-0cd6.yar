rule TTP_XOR_QUAD_CurrentVersionRun_0cd6 {
  strings:
    $key_0cd6 = { 5f b9 [2] 7b b7 [2] 50 9b [2] 7e b9 [2] 6a a2 [2] 65 b8 [2] 7b a5 [2] 79 a4 [2] 62 a2 [2] 7e a5 [2] 62 8a }

  condition:
    any of them
}