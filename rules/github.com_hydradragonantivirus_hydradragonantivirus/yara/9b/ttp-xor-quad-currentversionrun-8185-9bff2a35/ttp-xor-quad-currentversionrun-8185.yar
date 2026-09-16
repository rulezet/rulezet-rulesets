rule TTP_XOR_QUAD_CurrentVersionRun_8185 {
  strings:
    $key_8185 = { d2 ea [2] f6 e4 [2] dd c8 [2] f3 ea [2] e7 f1 [2] e8 eb [2] f6 f6 [2] f4 f7 [2] ef f1 [2] f3 f6 [2] ef d9 }

  condition:
    any of them
}