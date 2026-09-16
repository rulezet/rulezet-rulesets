rule TTP_XOR_QUAD_CurrentVersionRun_8111 {
  strings:
    $key_8111 = { d2 7e [2] f6 70 [2] dd 5c [2] f3 7e [2] e7 65 [2] e8 7f [2] f6 62 [2] f4 63 [2] ef 65 [2] f3 62 [2] ef 4d }

  condition:
    any of them
}