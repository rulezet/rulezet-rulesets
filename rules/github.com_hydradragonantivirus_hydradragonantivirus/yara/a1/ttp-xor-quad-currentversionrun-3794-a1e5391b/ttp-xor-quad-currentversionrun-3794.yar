rule TTP_XOR_QUAD_CurrentVersionRun_3794 {
  strings:
    $key_3794 = { 64 fb [2] 40 f5 [2] 6b d9 [2] 45 fb [2] 51 e0 [2] 5e fa [2] 40 e7 [2] 42 e6 [2] 59 e0 [2] 45 e7 [2] 59 c8 }

  condition:
    any of them
}