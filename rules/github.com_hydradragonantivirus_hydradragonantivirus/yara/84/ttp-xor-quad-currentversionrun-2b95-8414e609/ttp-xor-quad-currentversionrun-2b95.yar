rule TTP_XOR_QUAD_CurrentVersionRun_2b95 {
  strings:
    $key_2b95 = { 78 fa [2] 5c f4 [2] 77 d8 [2] 59 fa [2] 4d e1 [2] 42 fb [2] 5c e6 [2] 5e e7 [2] 45 e1 [2] 59 e6 [2] 45 c9 }

  condition:
    any of them
}