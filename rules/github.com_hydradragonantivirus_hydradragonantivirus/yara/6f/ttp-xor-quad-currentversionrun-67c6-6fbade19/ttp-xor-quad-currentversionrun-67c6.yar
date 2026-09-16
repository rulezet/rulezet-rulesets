rule TTP_XOR_QUAD_CurrentVersionRun_67c6 {
  strings:
    $key_67c6 = { 34 a9 [2] 10 a7 [2] 3b 8b [2] 15 a9 [2] 01 b2 [2] 0e a8 [2] 10 b5 [2] 12 b4 [2] 09 b2 [2] 15 b5 [2] 09 9a }

  condition:
    any of them
}