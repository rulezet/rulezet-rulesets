rule TTP_XOR_QUAD_CurrentVersionRun_46c6 {
  strings:
    $key_46c6 = { 15 a9 [2] 31 a7 [2] 1a 8b [2] 34 a9 [2] 20 b2 [2] 2f a8 [2] 31 b5 [2] 33 b4 [2] 28 b2 [2] 34 b5 [2] 28 9a }

  condition:
    any of them
}