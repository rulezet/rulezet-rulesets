rule TTP_XOR_QUAD_CurrentVersionRun_3394 {
  strings:
    $key_3394 = { 60 fb [2] 44 f5 [2] 6f d9 [2] 41 fb [2] 55 e0 [2] 5a fa [2] 44 e7 [2] 46 e6 [2] 5d e0 [2] 41 e7 [2] 5d c8 }

  condition:
    any of them
}