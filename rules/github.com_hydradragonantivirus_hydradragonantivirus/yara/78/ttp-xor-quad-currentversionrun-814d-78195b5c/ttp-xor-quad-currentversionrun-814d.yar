rule TTP_XOR_QUAD_CurrentVersionRun_814d {
  strings:
    $key_814d = { d2 22 [2] f6 2c [2] dd 00 [2] f3 22 [2] e7 39 [2] e8 23 [2] f6 3e [2] f4 3f [2] ef 39 [2] f3 3e [2] ef 11 }

  condition:
    any of them
}