rule TTP_XOR_QUAD_CurrentVersionRun_7589 {
  strings:
    $key_7589 = { 26 e6 [2] 02 e8 [2] 29 c4 [2] 07 e6 [2] 13 fd [2] 1c e7 [2] 02 fa [2] 00 fb [2] 1b fd [2] 07 fa [2] 1b d5 }

  condition:
    any of them
}