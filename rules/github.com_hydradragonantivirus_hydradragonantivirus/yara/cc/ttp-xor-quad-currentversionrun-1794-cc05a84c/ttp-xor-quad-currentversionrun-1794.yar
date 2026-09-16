rule TTP_XOR_QUAD_CurrentVersionRun_1794 {
  strings:
    $key_1794 = { 44 fb [2] 60 f5 [2] 4b d9 [2] 65 fb [2] 71 e0 [2] 7e fa [2] 60 e7 [2] 62 e6 [2] 79 e0 [2] 65 e7 [2] 79 c8 }

  condition:
    any of them
}