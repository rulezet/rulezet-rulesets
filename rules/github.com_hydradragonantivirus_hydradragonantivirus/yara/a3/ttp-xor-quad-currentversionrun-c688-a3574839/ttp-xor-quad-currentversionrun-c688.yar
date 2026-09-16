rule TTP_XOR_QUAD_CurrentVersionRun_c688 {
  strings:
    $key_c688 = { 95 e7 [2] b1 e9 [2] 9a c5 [2] b4 e7 [2] a0 fc [2] af e6 [2] b1 fb [2] b3 fa [2] a8 fc [2] b4 fb [2] a8 d4 }

  condition:
    any of them
}