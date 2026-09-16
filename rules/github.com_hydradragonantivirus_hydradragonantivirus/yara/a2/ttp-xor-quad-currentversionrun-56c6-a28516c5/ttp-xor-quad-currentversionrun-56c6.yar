rule TTP_XOR_QUAD_CurrentVersionRun_56c6 {
  strings:
    $key_56c6 = { 05 a9 [2] 21 a7 [2] 0a 8b [2] 24 a9 [2] 30 b2 [2] 3f a8 [2] 21 b5 [2] 23 b4 [2] 38 b2 [2] 24 b5 [2] 38 9a }

  condition:
    any of them
}