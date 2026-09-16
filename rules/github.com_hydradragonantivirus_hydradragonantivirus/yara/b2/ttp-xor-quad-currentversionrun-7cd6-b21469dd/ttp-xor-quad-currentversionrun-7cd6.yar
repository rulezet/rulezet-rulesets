rule TTP_XOR_QUAD_CurrentVersionRun_7cd6 {
  strings:
    $key_7cd6 = { 2f b9 [2] 0b b7 [2] 20 9b [2] 0e b9 [2] 1a a2 [2] 15 b8 [2] 0b a5 [2] 09 a4 [2] 12 a2 [2] 0e a5 [2] 12 8a }

  condition:
    any of them
}