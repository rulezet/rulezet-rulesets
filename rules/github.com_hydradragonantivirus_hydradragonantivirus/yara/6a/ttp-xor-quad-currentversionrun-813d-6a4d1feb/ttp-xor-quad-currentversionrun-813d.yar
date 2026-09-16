rule TTP_XOR_QUAD_CurrentVersionRun_813d {
  strings:
    $key_813d = { d2 52 [2] f6 5c [2] dd 70 [2] f3 52 [2] e7 49 [2] e8 53 [2] f6 4e [2] f4 4f [2] ef 49 [2] f3 4e [2] ef 61 }

  condition:
    any of them
}