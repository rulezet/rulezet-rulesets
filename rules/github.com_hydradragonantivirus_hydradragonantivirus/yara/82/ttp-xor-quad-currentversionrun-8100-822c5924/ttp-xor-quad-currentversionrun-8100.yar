rule TTP_XOR_QUAD_CurrentVersionRun_8100 {
  strings:
    $key_8100 = { d2 6f [2] f6 61 [2] dd 4d [2] f3 6f [2] e7 74 [2] e8 6e [2] f6 73 [2] f4 72 [2] ef 74 [2] f3 73 [2] ef 5c }

  condition:
    any of them
}