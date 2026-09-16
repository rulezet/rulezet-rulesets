rule TTP_XOR_QUAD_CurrentVersionRun_d489 {
  strings:
    $key_d489 = { 87 e6 [2] a3 e8 [2] 88 c4 [2] a6 e6 [2] b2 fd [2] bd e7 [2] a3 fa [2] a1 fb [2] ba fd [2] a6 fa [2] ba d5 }

  condition:
    any of them
}