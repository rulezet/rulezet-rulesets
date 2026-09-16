rule TTP_XOR_QUAD_CurrentVersionRun_b289 {
  strings:
    $key_b289 = { e1 e6 [2] c5 e8 [2] ee c4 [2] c0 e6 [2] d4 fd [2] db e7 [2] c5 fa [2] c7 fb [2] dc fd [2] c0 fa [2] dc d5 }

  condition:
    any of them
}