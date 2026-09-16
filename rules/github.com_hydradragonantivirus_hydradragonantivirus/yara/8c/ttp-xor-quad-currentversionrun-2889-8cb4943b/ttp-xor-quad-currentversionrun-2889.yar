rule TTP_XOR_QUAD_CurrentVersionRun_2889 {
  strings:
    $key_2889 = { 7b e6 [2] 5f e8 [2] 74 c4 [2] 5a e6 [2] 4e fd [2] 41 e7 [2] 5f fa [2] 5d fb [2] 46 fd [2] 5a fa [2] 46 d5 }

  condition:
    any of them
}