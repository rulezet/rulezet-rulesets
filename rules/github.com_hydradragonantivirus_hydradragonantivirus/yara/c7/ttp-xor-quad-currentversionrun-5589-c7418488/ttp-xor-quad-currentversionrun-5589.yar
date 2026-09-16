rule TTP_XOR_QUAD_CurrentVersionRun_5589 {
  strings:
    $key_5589 = { 06 e6 [2] 22 e8 [2] 09 c4 [2] 27 e6 [2] 33 fd [2] 3c e7 [2] 22 fa [2] 20 fb [2] 3b fd [2] 27 fa [2] 3b d5 }

  condition:
    any of them
}