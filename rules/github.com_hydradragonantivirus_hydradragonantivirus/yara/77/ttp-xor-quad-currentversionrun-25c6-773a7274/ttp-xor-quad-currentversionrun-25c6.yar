rule TTP_XOR_QUAD_CurrentVersionRun_25c6 {
  strings:
    $key_25c6 = { 76 a9 [2] 52 a7 [2] 79 8b [2] 57 a9 [2] 43 b2 [2] 4c a8 [2] 52 b5 [2] 50 b4 [2] 4b b2 [2] 57 b5 [2] 4b 9a }

  condition:
    any of them
}