rule TTP_XOR_QUAD_CurrentVersionRun_f294 {
  strings:
    $key_f294 = { a1 fb [2] 85 f5 [2] ae d9 [2] 80 fb [2] 94 e0 [2] 9b fa [2] 85 e7 [2] 87 e6 [2] 9c e0 [2] 80 e7 [2] 9c c8 }

  condition:
    any of them
}