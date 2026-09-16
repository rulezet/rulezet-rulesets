rule TTP_XOR_QUAD_CurrentVersionRun_7a89 {
  strings:
    $key_7a89 = { 29 e6 [2] 0d e8 [2] 26 c4 [2] 08 e6 [2] 1c fd [2] 13 e7 [2] 0d fa [2] 0f fb [2] 14 fd [2] 08 fa [2] 14 d5 }

  condition:
    any of them
}