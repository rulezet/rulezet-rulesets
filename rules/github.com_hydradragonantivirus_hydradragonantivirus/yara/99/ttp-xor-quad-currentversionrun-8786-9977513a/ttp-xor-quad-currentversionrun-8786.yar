rule TTP_XOR_QUAD_CurrentVersionRun_8786 {
  strings:
    $key_8786 = { d4 e9 [2] f0 e7 [2] db cb [2] f5 e9 [2] e1 f2 [2] ee e8 [2] f0 f5 [2] f2 f4 [2] e9 f2 [2] f5 f5 [2] e9 da }

  condition:
    any of them
}