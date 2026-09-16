rule TTP_XOR_QUAD_CurrentVersionRun_6594 {
  strings:
    $key_6594 = { 36 fb [2] 12 f5 [2] 39 d9 [2] 17 fb [2] 03 e0 [2] 0c fa [2] 12 e7 [2] 10 e6 [2] 0b e0 [2] 17 e7 [2] 0b c8 }

  condition:
    any of them
}