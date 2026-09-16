rule TTP_XOR_QUAD_CurrentVersionRun_5095 {
  strings:
    $key_5095 = { 03 fa [2] 27 f4 [2] 0c d8 [2] 22 fa [2] 36 e1 [2] 39 fb [2] 27 e6 [2] 25 e7 [2] 3e e1 [2] 22 e6 [2] 3e c9 }

  condition:
    any of them
}