rule TTP_XOR_QUAD_CurrentVersionRun_4694 {
  strings:
    $key_4694 = { 15 fb [2] 31 f5 [2] 1a d9 [2] 34 fb [2] 20 e0 [2] 2f fa [2] 31 e7 [2] 33 e6 [2] 28 e0 [2] 34 e7 [2] 28 c8 }

  condition:
    any of them
}