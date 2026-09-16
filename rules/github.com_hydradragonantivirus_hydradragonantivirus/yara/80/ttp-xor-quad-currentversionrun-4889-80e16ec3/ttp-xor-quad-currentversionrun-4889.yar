rule TTP_XOR_QUAD_CurrentVersionRun_4889 {
  strings:
    $key_4889 = { 1b e6 [2] 3f e8 [2] 14 c4 [2] 3a e6 [2] 2e fd [2] 21 e7 [2] 3f fa [2] 3d fb [2] 26 fd [2] 3a fa [2] 26 d5 }

  condition:
    any of them
}