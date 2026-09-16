rule TTP_XOR_QUAD_CurrentVersionRun_f089 {
  strings:
    $key_f089 = { a3 e6 [2] 87 e8 [2] ac c4 [2] 82 e6 [2] 96 fd [2] 99 e7 [2] 87 fa [2] 85 fb [2] 9e fd [2] 82 fa [2] 9e d5 }

  condition:
    any of them
}