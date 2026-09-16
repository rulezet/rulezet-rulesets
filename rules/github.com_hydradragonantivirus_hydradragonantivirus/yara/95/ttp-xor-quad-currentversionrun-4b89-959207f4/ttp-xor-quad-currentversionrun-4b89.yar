rule TTP_XOR_QUAD_CurrentVersionRun_4b89 {
  strings:
    $key_4b89 = { 18 e6 [2] 3c e8 [2] 17 c4 [2] 39 e6 [2] 2d fd [2] 22 e7 [2] 3c fa [2] 3e fb [2] 25 fd [2] 39 fa [2] 25 d5 }

  condition:
    any of them
}