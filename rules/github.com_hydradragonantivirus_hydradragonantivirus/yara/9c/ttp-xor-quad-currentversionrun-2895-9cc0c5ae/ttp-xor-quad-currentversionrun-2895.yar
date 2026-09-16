rule TTP_XOR_QUAD_CurrentVersionRun_2895 {
  strings:
    $key_2895 = { 7b fa [2] 5f f4 [2] 74 d8 [2] 5a fa [2] 4e e1 [2] 41 fb [2] 5f e6 [2] 5d e7 [2] 46 e1 [2] 5a e6 [2] 46 c9 }

  condition:
    any of them
}