rule TTP_XOR_QUAD_CurrentVersionRun_5989 {
  strings:
    $key_5989 = { 0a e6 [2] 2e e8 [2] 05 c4 [2] 2b e6 [2] 3f fd [2] 30 e7 [2] 2e fa [2] 2c fb [2] 37 fd [2] 2b fa [2] 37 d5 }

  condition:
    any of them
}