rule TTP_XOR_QUAD_CurrentVersionRun_2b89 {
  strings:
    $key_2b89 = { 78 e6 [2] 5c e8 [2] 77 c4 [2] 59 e6 [2] 4d fd [2] 42 e7 [2] 5c fa [2] 5e fb [2] 45 fd [2] 59 fa [2] 45 d5 }

  condition:
    any of them
}