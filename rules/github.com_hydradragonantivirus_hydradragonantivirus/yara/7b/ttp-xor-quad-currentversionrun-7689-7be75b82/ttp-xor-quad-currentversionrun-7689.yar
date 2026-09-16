rule TTP_XOR_QUAD_CurrentVersionRun_7689 {
  strings:
    $key_7689 = { 25 e6 [2] 01 e8 [2] 2a c4 [2] 04 e6 [2] 10 fd [2] 1f e7 [2] 01 fa [2] 03 fb [2] 18 fd [2] 04 fa [2] 18 d5 }

  condition:
    any of them
}