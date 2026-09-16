rule TTP_XOR_QUAD_CurrentVersionRun_816d {
  strings:
    $key_816d = { d2 02 [2] f6 0c [2] dd 20 [2] f3 02 [2] e7 19 [2] e8 03 [2] f6 1e [2] f4 1f [2] ef 19 [2] f3 1e [2] ef 31 }

  condition:
    any of them
}