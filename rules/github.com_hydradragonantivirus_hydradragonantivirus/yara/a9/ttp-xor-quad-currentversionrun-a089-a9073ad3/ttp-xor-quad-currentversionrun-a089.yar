rule TTP_XOR_QUAD_CurrentVersionRun_a089 {
  strings:
    $key_a089 = { f3 e6 [2] d7 e8 [2] fc c4 [2] d2 e6 [2] c6 fd [2] c9 e7 [2] d7 fa [2] d5 fb [2] ce fd [2] d2 fa [2] ce d5 }

  condition:
    any of them
}