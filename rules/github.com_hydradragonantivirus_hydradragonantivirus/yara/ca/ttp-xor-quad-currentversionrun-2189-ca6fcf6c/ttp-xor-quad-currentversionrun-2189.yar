rule TTP_XOR_QUAD_CurrentVersionRun_2189 {
  strings:
    $key_2189 = { 72 e6 [2] 56 e8 [2] 7d c4 [2] 53 e6 [2] 47 fd [2] 48 e7 [2] 56 fa [2] 54 fb [2] 4f fd [2] 53 fa [2] 4f d5 }

  condition:
    any of them
}