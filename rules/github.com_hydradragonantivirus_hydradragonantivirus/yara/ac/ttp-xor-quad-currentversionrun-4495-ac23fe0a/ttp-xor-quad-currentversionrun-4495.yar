rule TTP_XOR_QUAD_CurrentVersionRun_4495 {
  strings:
    $key_4495 = { 17 fa [2] 33 f4 [2] 18 d8 [2] 36 fa [2] 22 e1 [2] 2d fb [2] 33 e6 [2] 31 e7 [2] 2a e1 [2] 36 e6 [2] 2a c9 }

  condition:
    any of them
}