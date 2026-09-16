rule TTP_XOR_QUAD_CurrentVersionRun_3395 {
  strings:
    $key_3395 = { 60 fa [2] 44 f4 [2] 6f d8 [2] 41 fa [2] 55 e1 [2] 5a fb [2] 44 e6 [2] 46 e7 [2] 5d e1 [2] 41 e6 [2] 5d c9 }

  condition:
    any of them
}