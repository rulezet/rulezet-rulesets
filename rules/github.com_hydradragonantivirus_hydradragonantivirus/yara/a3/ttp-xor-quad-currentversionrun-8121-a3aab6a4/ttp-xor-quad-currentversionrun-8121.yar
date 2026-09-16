rule TTP_XOR_QUAD_CurrentVersionRun_8121 {
  strings:
    $key_8121 = { d2 4e [2] f6 40 [2] dd 6c [2] f3 4e [2] e7 55 [2] e8 4f [2] f6 52 [2] f4 53 [2] ef 55 [2] f3 52 [2] ef 7d }

  condition:
    any of them
}