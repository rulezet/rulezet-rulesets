rule TTP_XOR_QUAD_CurrentVersionRun_814f {
  strings:
    $key_814f = { d2 20 [2] f6 2e [2] dd 02 [2] f3 20 [2] e7 3b [2] e8 21 [2] f6 3c [2] f4 3d [2] ef 3b [2] f3 3c [2] ef 13 }

  condition:
    any of them
}