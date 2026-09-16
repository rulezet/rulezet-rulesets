rule TTP_XOR_QUAD_CurrentVersionRun_af89 {
  strings:
    $key_af89 = { fc e6 [2] d8 e8 [2] f3 c4 [2] dd e6 [2] c9 fd [2] c6 e7 [2] d8 fa [2] da fb [2] c1 fd [2] dd fa [2] c1 d5 }

  condition:
    any of them
}