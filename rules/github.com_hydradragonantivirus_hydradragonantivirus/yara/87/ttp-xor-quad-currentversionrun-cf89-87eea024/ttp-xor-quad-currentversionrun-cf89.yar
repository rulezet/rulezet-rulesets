rule TTP_XOR_QUAD_CurrentVersionRun_cf89 {
  strings:
    $key_cf89 = { 9c e6 [2] b8 e8 [2] 93 c4 [2] bd e6 [2] a9 fd [2] a6 e7 [2] b8 fa [2] ba fb [2] a1 fd [2] bd fa [2] a1 d5 }

  condition:
    any of them
}