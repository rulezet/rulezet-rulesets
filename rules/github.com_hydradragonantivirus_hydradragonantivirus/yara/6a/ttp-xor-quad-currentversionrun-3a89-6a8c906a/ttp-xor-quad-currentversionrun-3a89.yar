rule TTP_XOR_QUAD_CurrentVersionRun_3a89 {
  strings:
    $key_3a89 = { 69 e6 [2] 4d e8 [2] 66 c4 [2] 48 e6 [2] 5c fd [2] 53 e7 [2] 4d fa [2] 4f fb [2] 54 fd [2] 48 fa [2] 54 d5 }

  condition:
    any of them
}