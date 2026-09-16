rule TTP_XOR_QUAD_CurrentVersionRun_8d89 {
  strings:
    $key_8d89 = { de e6 [2] fa e8 [2] d1 c4 [2] ff e6 [2] eb fd [2] e4 e7 [2] fa fa [2] f8 fb [2] e3 fd [2] ff fa [2] e3 d5 }

  condition:
    any of them
}