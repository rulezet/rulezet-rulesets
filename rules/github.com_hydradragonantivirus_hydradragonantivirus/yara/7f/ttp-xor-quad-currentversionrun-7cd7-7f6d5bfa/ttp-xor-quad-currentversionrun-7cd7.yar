rule TTP_XOR_QUAD_CurrentVersionRun_7cd7 {
  strings:
    $key_7cd7 = { 2f b8 [2] 0b b6 [2] 20 9a [2] 0e b8 [2] 1a a3 [2] 15 b9 [2] 0b a4 [2] 09 a5 [2] 12 a3 [2] 0e a4 [2] 12 8b }

  condition:
    any of them
}