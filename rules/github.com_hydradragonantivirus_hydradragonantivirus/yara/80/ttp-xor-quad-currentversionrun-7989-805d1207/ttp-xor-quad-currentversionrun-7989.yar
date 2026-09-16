rule TTP_XOR_QUAD_CurrentVersionRun_7989 {
  strings:
    $key_7989 = { 2a e6 [2] 0e e8 [2] 25 c4 [2] 0b e6 [2] 1f fd [2] 10 e7 [2] 0e fa [2] 0c fb [2] 17 fd [2] 0b fa [2] 17 d5 }

  condition:
    any of them
}