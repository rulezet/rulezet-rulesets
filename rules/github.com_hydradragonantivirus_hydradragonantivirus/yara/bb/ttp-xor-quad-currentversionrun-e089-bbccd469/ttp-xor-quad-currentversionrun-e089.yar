rule TTP_XOR_QUAD_CurrentVersionRun_e089 {
  strings:
    $key_e089 = { b3 e6 [2] 97 e8 [2] bc c4 [2] 92 e6 [2] 86 fd [2] 89 e7 [2] 97 fa [2] 95 fb [2] 8e fd [2] 92 fa [2] 8e d5 }

  condition:
    any of them
}