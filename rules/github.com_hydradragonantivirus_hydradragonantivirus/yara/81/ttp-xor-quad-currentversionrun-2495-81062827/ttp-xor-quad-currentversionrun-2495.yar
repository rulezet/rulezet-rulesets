rule TTP_XOR_QUAD_CurrentVersionRun_2495 {
  strings:
    $key_2495 = { 77 fa [2] 53 f4 [2] 78 d8 [2] 56 fa [2] 42 e1 [2] 4d fb [2] 53 e6 [2] 51 e7 [2] 4a e1 [2] 56 e6 [2] 4a c9 }

  condition:
    any of them
}