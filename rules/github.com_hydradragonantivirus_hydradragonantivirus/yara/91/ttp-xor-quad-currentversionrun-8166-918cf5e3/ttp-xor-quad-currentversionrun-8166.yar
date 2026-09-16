rule TTP_XOR_QUAD_CurrentVersionRun_8166 {
  strings:
    $key_8166 = { d2 09 [2] f6 07 [2] dd 2b [2] f3 09 [2] e7 12 [2] e8 08 [2] f6 15 [2] f4 14 [2] ef 12 [2] f3 15 [2] ef 3a }

  condition:
    any of them
}