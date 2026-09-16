rule TTP_XOR_QUAD_CurrentVersionRun_4189 {
  strings:
    $key_4189 = { 12 e6 [2] 36 e8 [2] 1d c4 [2] 33 e6 [2] 27 fd [2] 28 e7 [2] 36 fa [2] 34 fb [2] 2f fd [2] 33 fa [2] 2f d5 }

  condition:
    any of them
}