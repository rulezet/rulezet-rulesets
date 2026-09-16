rule TTP_XOR_QUAD_CurrentVersionRun_8a89 {
  strings:
    $key_8a89 = { d9 e6 [2] fd e8 [2] d6 c4 [2] f8 e6 [2] ec fd [2] e3 e7 [2] fd fa [2] ff fb [2] e4 fd [2] f8 fa [2] e4 d5 }

  condition:
    any of them
}