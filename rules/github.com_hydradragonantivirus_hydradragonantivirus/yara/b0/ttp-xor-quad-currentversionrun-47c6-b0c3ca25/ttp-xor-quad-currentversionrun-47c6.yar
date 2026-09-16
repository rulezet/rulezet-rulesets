rule TTP_XOR_QUAD_CurrentVersionRun_47c6 {
  strings:
    $key_47c6 = { 14 a9 [2] 30 a7 [2] 1b 8b [2] 35 a9 [2] 21 b2 [2] 2e a8 [2] 30 b5 [2] 32 b4 [2] 29 b2 [2] 35 b5 [2] 29 9a }

  condition:
    any of them
}