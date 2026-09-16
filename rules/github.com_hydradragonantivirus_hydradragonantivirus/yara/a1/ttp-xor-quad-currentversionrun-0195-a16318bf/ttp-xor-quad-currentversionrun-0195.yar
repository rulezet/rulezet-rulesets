rule TTP_XOR_QUAD_CurrentVersionRun_0195 {
  strings:
    $key_0195 = { 52 fa [2] 76 f4 [2] 5d d8 [2] 73 fa [2] 67 e1 [2] 68 fb [2] 76 e6 [2] 74 e7 [2] 6f e1 [2] 73 e6 [2] 6f c9 }

  condition:
    any of them
}