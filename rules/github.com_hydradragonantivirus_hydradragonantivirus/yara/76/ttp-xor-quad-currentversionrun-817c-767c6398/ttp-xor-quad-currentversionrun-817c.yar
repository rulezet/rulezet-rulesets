rule TTP_XOR_QUAD_CurrentVersionRun_817c {
  strings:
    $key_817c = { d2 13 [2] f6 1d [2] dd 31 [2] f3 13 [2] e7 08 [2] e8 12 [2] f6 0f [2] f4 0e [2] ef 08 [2] f3 0f [2] ef 20 }

  condition:
    any of them
}