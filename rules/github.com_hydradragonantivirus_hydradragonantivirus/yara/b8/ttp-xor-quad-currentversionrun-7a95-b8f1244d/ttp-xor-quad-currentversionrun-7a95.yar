rule TTP_XOR_QUAD_CurrentVersionRun_7a95 {
  strings:
    $key_7a95 = { 29 fa [2] 0d f4 [2] 26 d8 [2] 08 fa [2] 1c e1 [2] 13 fb [2] 0d e6 [2] 0f e7 [2] 14 e1 [2] 08 e6 [2] 14 c9 }

  condition:
    any of them
}