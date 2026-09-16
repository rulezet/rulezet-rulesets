rule TTP_XOR_QUAD_CurrentVersionRun_0a89 {
  strings:
    $key_0a89 = { 59 e6 [2] 7d e8 [2] 56 c4 [2] 78 e6 [2] 6c fd [2] 63 e7 [2] 7d fa [2] 7f fb [2] 64 fd [2] 78 fa [2] 64 d5 }

  condition:
    any of them
}