rule TTP_XOR_QUAD_CurrentVersionRun_0cd7 {
  strings:
    $key_0cd7 = { 5f b8 [2] 7b b6 [2] 50 9a [2] 7e b8 [2] 6a a3 [2] 65 b9 [2] 7b a4 [2] 79 a5 [2] 62 a3 [2] 7e a4 [2] 62 8b }

  condition:
    any of them
}