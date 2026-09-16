rule TTP_XOR_QUAD_CurrentVersionRun_c389 {
  strings:
    $key_c389 = { 90 e6 [2] b4 e8 [2] 9f c4 [2] b1 e6 [2] a5 fd [2] aa e7 [2] b4 fa [2] b6 fb [2] ad fd [2] b1 fa [2] ad d5 }

  condition:
    any of them
}