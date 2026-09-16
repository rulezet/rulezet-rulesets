rule TTP_XOR_QUAD_CurrentVersionRun_6694 {
  strings:
    $key_6694 = { 35 fb [2] 11 f5 [2] 3a d9 [2] 14 fb [2] 00 e0 [2] 0f fa [2] 11 e7 [2] 13 e6 [2] 08 e0 [2] 14 e7 [2] 08 c8 }

  condition:
    any of them
}