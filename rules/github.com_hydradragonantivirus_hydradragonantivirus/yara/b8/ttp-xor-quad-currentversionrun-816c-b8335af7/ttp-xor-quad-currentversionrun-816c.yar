rule TTP_XOR_QUAD_CurrentVersionRun_816c {
  strings:
    $key_816c = { d2 03 [2] f6 0d [2] dd 21 [2] f3 03 [2] e7 18 [2] e8 02 [2] f6 1f [2] f4 1e [2] ef 18 [2] f3 1f [2] ef 30 }

  condition:
    any of them
}