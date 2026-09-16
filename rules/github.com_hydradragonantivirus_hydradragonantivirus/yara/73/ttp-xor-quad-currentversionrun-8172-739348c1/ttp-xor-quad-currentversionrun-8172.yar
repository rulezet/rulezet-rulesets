rule TTP_XOR_QUAD_CurrentVersionRun_8172 {
  strings:
    $key_8172 = { d2 1d [2] f6 13 [2] dd 3f [2] f3 1d [2] e7 06 [2] e8 1c [2] f6 01 [2] f4 00 [2] ef 06 [2] f3 01 [2] ef 2e }

  condition:
    any of them
}