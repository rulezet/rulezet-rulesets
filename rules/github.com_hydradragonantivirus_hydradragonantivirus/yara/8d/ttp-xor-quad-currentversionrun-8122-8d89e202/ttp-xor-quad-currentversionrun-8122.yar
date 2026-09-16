rule TTP_XOR_QUAD_CurrentVersionRun_8122 {
  strings:
    $key_8122 = { d2 4d [2] f6 43 [2] dd 6f [2] f3 4d [2] e7 56 [2] e8 4c [2] f6 51 [2] f4 50 [2] ef 56 [2] f3 51 [2] ef 7e }

  condition:
    any of them
}