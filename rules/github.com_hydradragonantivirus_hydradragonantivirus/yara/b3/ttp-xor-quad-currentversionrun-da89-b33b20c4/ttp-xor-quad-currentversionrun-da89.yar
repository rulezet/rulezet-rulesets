rule TTP_XOR_QUAD_CurrentVersionRun_da89 {
  strings:
    $key_da89 = { 89 e6 [2] ad e8 [2] 86 c4 [2] a8 e6 [2] bc fd [2] b3 e7 [2] ad fa [2] af fb [2] b4 fd [2] a8 fa [2] b4 d5 }

  condition:
    any of them
}