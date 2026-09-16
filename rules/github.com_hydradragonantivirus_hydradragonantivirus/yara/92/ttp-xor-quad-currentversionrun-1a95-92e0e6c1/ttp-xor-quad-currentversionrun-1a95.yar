rule TTP_XOR_QUAD_CurrentVersionRun_1a95 {
  strings:
    $key_1a95 = { 49 fa [2] 6d f4 [2] 46 d8 [2] 68 fa [2] 7c e1 [2] 73 fb [2] 6d e6 [2] 6f e7 [2] 74 e1 [2] 68 e6 [2] 74 c9 }

  condition:
    any of them
}