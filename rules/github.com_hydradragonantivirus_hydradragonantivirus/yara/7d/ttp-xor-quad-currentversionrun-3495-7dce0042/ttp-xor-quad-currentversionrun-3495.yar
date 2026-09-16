rule TTP_XOR_QUAD_CurrentVersionRun_3495 {
  strings:
    $key_3495 = { 67 fa [2] 43 f4 [2] 68 d8 [2] 46 fa [2] 52 e1 [2] 5d fb [2] 43 e6 [2] 41 e7 [2] 5a e1 [2] 46 e6 [2] 5a c9 }

  condition:
    any of them
}