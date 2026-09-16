rule TTP_XOR_QUAD_CurrentVersionRun_5889 {
  strings:
    $key_5889 = { 0b e6 [2] 2f e8 [2] 04 c4 [2] 2a e6 [2] 3e fd [2] 31 e7 [2] 2f fa [2] 2d fb [2] 36 fd [2] 2a fa [2] 36 d5 }

  condition:
    any of them
}