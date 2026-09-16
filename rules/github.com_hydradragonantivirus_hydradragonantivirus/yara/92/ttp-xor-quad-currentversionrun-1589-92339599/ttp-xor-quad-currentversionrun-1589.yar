rule TTP_XOR_QUAD_CurrentVersionRun_1589 {
  strings:
    $key_1589 = { 46 e6 [2] 62 e8 [2] 49 c4 [2] 67 e6 [2] 73 fd [2] 7c e7 [2] 62 fa [2] 60 fb [2] 7b fd [2] 67 fa [2] 7b d5 }

  condition:
    any of them
}