rule TTP_XOR_QUAD_CurrentVersionRun_5794 {
  strings:
    $key_5794 = { 04 fb [2] 20 f5 [2] 0b d9 [2] 25 fb [2] 31 e0 [2] 3e fa [2] 20 e7 [2] 22 e6 [2] 39 e0 [2] 25 e7 [2] 39 c8 }

  condition:
    any of them
}