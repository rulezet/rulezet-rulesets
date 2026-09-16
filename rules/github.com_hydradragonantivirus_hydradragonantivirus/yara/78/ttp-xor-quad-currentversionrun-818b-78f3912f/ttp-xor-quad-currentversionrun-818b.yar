rule TTP_XOR_QUAD_CurrentVersionRun_818b {
  strings:
    $key_818b = { d2 e4 [2] f6 ea [2] dd c6 [2] f3 e4 [2] e7 ff [2] e8 e5 [2] f6 f8 [2] f4 f9 [2] ef ff [2] f3 f8 [2] ef d7 }

  condition:
    any of them
}