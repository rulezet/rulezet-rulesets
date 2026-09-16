rule TTP_XOR_QUAD_CurrentVersionRun_f594 {
  strings:
    $key_f594 = { a6 fb [2] 82 f5 [2] a9 d9 [2] 87 fb [2] 93 e0 [2] 9c fa [2] 82 e7 [2] 80 e6 [2] 9b e0 [2] 87 e7 [2] 9b c8 }

  condition:
    any of them
}