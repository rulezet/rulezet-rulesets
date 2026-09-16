rule TTP_XOR_QUAD_CurrentVersionRun_1889 {
  strings:
    $key_1889 = { 4b e6 [2] 6f e8 [2] 44 c4 [2] 6a e6 [2] 7e fd [2] 71 e7 [2] 6f fa [2] 6d fb [2] 76 fd [2] 6a fa [2] 76 d5 }

  condition:
    any of them
}