rule TTP_XOR_QUAD_CurrentVersionRun_817d {
  strings:
    $key_817d = { d2 12 [2] f6 1c [2] dd 30 [2] f3 12 [2] e7 09 [2] e8 13 [2] f6 0e [2] f4 0f [2] ef 09 [2] f3 0e [2] ef 21 }

  condition:
    any of them
}