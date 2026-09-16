rule TTP_XOR_QUAD_CurrentVersionRun_ce94 {
  strings:
    $key_ce94 = { 9d fb [2] b9 f5 [2] 92 d9 [2] bc fb [2] a8 e0 [2] a7 fa [2] b9 e7 [2] bb e6 [2] a0 e0 [2] bc e7 [2] a0 c8 }

  condition:
    any of them
}