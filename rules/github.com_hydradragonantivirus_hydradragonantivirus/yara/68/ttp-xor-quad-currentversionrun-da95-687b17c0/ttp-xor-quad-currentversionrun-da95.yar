rule TTP_XOR_QUAD_CurrentVersionRun_da95 {
  strings:
    $key_da95 = { 89 fa [2] ad f4 [2] 86 d8 [2] a8 fa [2] bc e1 [2] b3 fb [2] ad e6 [2] af e7 [2] b4 e1 [2] a8 e6 [2] b4 c9 }

  condition:
    any of them
}