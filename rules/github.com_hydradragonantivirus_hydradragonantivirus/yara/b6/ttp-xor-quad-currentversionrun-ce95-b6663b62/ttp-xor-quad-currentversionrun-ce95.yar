rule TTP_XOR_QUAD_CurrentVersionRun_ce95 {
  strings:
    $key_ce95 = { 9d fa [2] b9 f4 [2] 92 d8 [2] bc fa [2] a8 e1 [2] a7 fb [2] b9 e6 [2] bb e7 [2] a0 e1 [2] bc e6 [2] a0 c9 }

  condition:
    any of them
}