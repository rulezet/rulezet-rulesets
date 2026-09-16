rule TTP_XOR_QUAD_CurrentVersionRun_8140 {
  strings:
    $key_8140 = { d2 2f [2] f6 21 [2] dd 0d [2] f3 2f [2] e7 34 [2] e8 2e [2] f6 33 [2] f4 32 [2] ef 34 [2] f3 33 [2] ef 1c }

  condition:
    any of them
}