rule TTP_XOR_QUAD_CurrentVersionRun_8101 {
  strings:
    $key_8101 = { d2 6e [2] f6 60 [2] dd 4c [2] f3 6e [2] e7 75 [2] e8 6f [2] f6 72 [2] f4 73 [2] ef 75 [2] f3 72 [2] ef 5d }

  condition:
    any of them
}