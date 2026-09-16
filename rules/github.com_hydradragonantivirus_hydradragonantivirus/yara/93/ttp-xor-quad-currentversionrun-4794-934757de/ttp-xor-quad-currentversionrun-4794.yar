rule TTP_XOR_QUAD_CurrentVersionRun_4794 {
  strings:
    $key_4794 = { 14 fb [2] 30 f5 [2] 1b d9 [2] 35 fb [2] 21 e0 [2] 2e fa [2] 30 e7 [2] 32 e6 [2] 29 e0 [2] 35 e7 [2] 29 c8 }

  condition:
    any of them
}