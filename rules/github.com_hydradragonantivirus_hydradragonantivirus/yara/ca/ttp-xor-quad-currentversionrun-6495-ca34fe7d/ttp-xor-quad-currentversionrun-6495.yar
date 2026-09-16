rule TTP_XOR_QUAD_CurrentVersionRun_6495 {
  strings:
    $key_6495 = { 37 fa [2] 13 f4 [2] 38 d8 [2] 16 fa [2] 02 e1 [2] 0d fb [2] 13 e6 [2] 11 e7 [2] 0a e1 [2] 16 e6 [2] 0a c9 }

  condition:
    any of them
}