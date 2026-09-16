rule TTP_XOR_QUAD_CurrentVersionRun_81f3 {
  strings:
    $key_81f3 = { d2 9c [2] f6 92 [2] dd be [2] f3 9c [2] e7 87 [2] e8 9d [2] f6 80 [2] f4 81 [2] ef 87 [2] f3 80 [2] ef af }

  condition:
    any of them
}