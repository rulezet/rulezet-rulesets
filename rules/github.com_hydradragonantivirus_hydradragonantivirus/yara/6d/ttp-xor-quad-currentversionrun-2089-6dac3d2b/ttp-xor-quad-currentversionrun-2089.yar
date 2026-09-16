rule TTP_XOR_QUAD_CurrentVersionRun_2089 {
  strings:
    $key_2089 = { 73 e6 [2] 57 e8 [2] 7c c4 [2] 52 e6 [2] 46 fd [2] 49 e7 [2] 57 fa [2] 55 fb [2] 4e fd [2] 52 fa [2] 4e d5 }

  condition:
    any of them
}