rule TTP_XOR_QUAD_CurrentVersionRun_2394 {
  strings:
    $key_2394 = { 70 fb [2] 54 f5 [2] 7f d9 [2] 51 fb [2] 45 e0 [2] 4a fa [2] 54 e7 [2] 56 e6 [2] 4d e0 [2] 51 e7 [2] 4d c8 }

  condition:
    any of them
}