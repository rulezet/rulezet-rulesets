rule TTP_XOR_QUAD_CurrentVersionRun_e095 {
  strings:
    $key_e095 = { b3 fa [2] 97 f4 [2] bc d8 [2] 92 fa [2] 86 e1 [2] 89 fb [2] 97 e6 [2] 95 e7 [2] 8e e1 [2] 92 e6 [2] 8e c9 }

  condition:
    any of them
}