rule TTP_XOR_QUAD_CurrentVersionRun_814c {
  strings:
    $key_814c = { d2 23 [2] f6 2d [2] dd 01 [2] f3 23 [2] e7 38 [2] e8 22 [2] f6 3f [2] f4 3e [2] ef 38 [2] f3 3f [2] ef 10 }

  condition:
    any of them
}