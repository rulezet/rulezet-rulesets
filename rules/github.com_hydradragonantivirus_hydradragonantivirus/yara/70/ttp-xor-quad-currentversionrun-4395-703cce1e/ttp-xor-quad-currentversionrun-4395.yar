rule TTP_XOR_QUAD_CurrentVersionRun_4395 {
  strings:
    $key_4395 = { 10 fa [2] 34 f4 [2] 1f d8 [2] 31 fa [2] 25 e1 [2] 2a fb [2] 34 e6 [2] 36 e7 [2] 2d e1 [2] 31 e6 [2] 2d c9 }

  condition:
    any of them
}