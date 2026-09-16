rule TTP_XOR_QUAD_CurrentVersionRun_3694 {
  strings:
    $key_3694 = { 65 fb [2] 41 f5 [2] 6a d9 [2] 44 fb [2] 50 e0 [2] 5f fa [2] 41 e7 [2] 43 e6 [2] 58 e0 [2] 44 e7 [2] 58 c8 }

  condition:
    any of them
}