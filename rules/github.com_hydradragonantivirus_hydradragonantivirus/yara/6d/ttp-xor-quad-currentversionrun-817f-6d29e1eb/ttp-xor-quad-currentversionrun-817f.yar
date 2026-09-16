rule TTP_XOR_QUAD_CurrentVersionRun_817f {
  strings:
    $key_817f = { d2 10 [2] f6 1e [2] dd 32 [2] f3 10 [2] e7 0b [2] e8 11 [2] f6 0c [2] f4 0d [2] ef 0b [2] f3 0c [2] ef 23 }

  condition:
    any of them
}