rule TTP_XOR_QUAD_CurrentVersionRun_2594 {
  strings:
    $key_2594 = { 76 fb [2] 52 f5 [2] 79 d9 [2] 57 fb [2] 43 e0 [2] 4c fa [2] 52 e7 [2] 50 e6 [2] 4b e0 [2] 57 e7 [2] 4b c8 }

  condition:
    any of them
}