rule TTP_XOR_QUAD_CurrentVersionRun_8151 {
  strings:
    $key_8151 = { d2 3e [2] f6 30 [2] dd 1c [2] f3 3e [2] e7 25 [2] e8 3f [2] f6 22 [2] f4 23 [2] ef 25 [2] f3 22 [2] ef 0d }

  condition:
    any of them
}