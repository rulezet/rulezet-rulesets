rule TTP_XOR_QUAD_CurrentVersionRun_ca95 {
  strings:
    $key_ca95 = { 99 fa [2] bd f4 [2] 96 d8 [2] b8 fa [2] ac e1 [2] a3 fb [2] bd e6 [2] bf e7 [2] a4 e1 [2] b8 e6 [2] a4 c9 }

  condition:
    any of them
}