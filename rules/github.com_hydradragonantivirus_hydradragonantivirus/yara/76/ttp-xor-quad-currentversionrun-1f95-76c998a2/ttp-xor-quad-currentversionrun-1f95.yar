rule TTP_XOR_QUAD_CurrentVersionRun_1f95 {
  strings:
    $key_1f95 = { 4c fa [2] 68 f4 [2] 43 d8 [2] 6d fa [2] 79 e1 [2] 76 fb [2] 68 e6 [2] 6a e7 [2] 71 e1 [2] 6d e6 [2] 71 c9 }

  condition:
    any of them
}