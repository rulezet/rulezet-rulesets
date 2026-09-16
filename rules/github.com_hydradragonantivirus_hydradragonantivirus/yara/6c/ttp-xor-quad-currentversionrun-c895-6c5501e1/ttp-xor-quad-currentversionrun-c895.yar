rule TTP_XOR_QUAD_CurrentVersionRun_c895 {
  strings:
    $key_c895 = { 9b fa [2] bf f4 [2] 94 d8 [2] ba fa [2] ae e1 [2] a1 fb [2] bf e6 [2] bd e7 [2] a6 e1 [2] ba e6 [2] a6 c9 }

  condition:
    any of them
}