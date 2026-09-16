rule TTP_XOR_QUAD_CurrentVersionRun_e589 {
  strings:
    $key_e589 = { b6 e6 [2] 92 e8 [2] b9 c4 [2] 97 e6 [2] 83 fd [2] 8c e7 [2] 92 fa [2] 90 fb [2] 8b fd [2] 97 fa [2] 8b d5 }

  condition:
    any of them
}