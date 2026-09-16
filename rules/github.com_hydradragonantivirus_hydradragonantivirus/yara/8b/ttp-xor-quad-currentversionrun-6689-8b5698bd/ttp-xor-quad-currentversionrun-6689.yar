rule TTP_XOR_QUAD_CurrentVersionRun_6689 {
  strings:
    $key_6689 = { 35 e6 [2] 11 e8 [2] 3a c4 [2] 14 e6 [2] 00 fd [2] 0f e7 [2] 11 fa [2] 13 fb [2] 08 fd [2] 14 fa [2] 08 d5 }

  condition:
    any of them
}