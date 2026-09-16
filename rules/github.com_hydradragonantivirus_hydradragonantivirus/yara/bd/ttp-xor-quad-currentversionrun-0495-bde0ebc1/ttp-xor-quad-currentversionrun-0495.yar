rule TTP_XOR_QUAD_CurrentVersionRun_0495 {
  strings:
    $key_0495 = { 57 fa [2] 73 f4 [2] 58 d8 [2] 76 fa [2] 62 e1 [2] 6d fb [2] 73 e6 [2] 71 e7 [2] 6a e1 [2] 76 e6 [2] 6a c9 }

  condition:
    any of them
}