rule TTP_XOR_QUAD_CurrentVersionRun_4489 {
  strings:
    $key_4489 = { 17 e6 [2] 33 e8 [2] 18 c4 [2] 36 e6 [2] 22 fd [2] 2d e7 [2] 33 fa [2] 31 fb [2] 2a fd [2] 36 fa [2] 2a d5 }

  condition:
    any of them
}