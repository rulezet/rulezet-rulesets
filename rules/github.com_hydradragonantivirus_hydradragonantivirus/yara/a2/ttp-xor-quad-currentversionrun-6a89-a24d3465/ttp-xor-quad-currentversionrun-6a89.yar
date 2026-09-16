rule TTP_XOR_QUAD_CurrentVersionRun_6a89 {
  strings:
    $key_6a89 = { 39 e6 [2] 1d e8 [2] 36 c4 [2] 18 e6 [2] 0c fd [2] 03 e7 [2] 1d fa [2] 1f fb [2] 04 fd [2] 18 fa [2] 04 d5 }

  condition:
    any of them
}