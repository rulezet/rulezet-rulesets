rule TTP_XOR_QUAD_CurrentVersionRun_1694 {
  strings:
    $key_1694 = { 45 fb [2] 61 f5 [2] 4a d9 [2] 64 fb [2] 70 e0 [2] 7f fa [2] 61 e7 [2] 63 e6 [2] 78 e0 [2] 64 e7 [2] 78 c8 }

  condition:
    any of them
}