rule TTP_XOR_QUAD_CurrentVersionRun_2489 {
  strings:
    $key_2489 = { 77 e6 [2] 53 e8 [2] 78 c4 [2] 56 e6 [2] 42 fd [2] 4d e7 [2] 53 fa [2] 51 fb [2] 4a fd [2] 56 fa [2] 4a d5 }

  condition:
    any of them
}