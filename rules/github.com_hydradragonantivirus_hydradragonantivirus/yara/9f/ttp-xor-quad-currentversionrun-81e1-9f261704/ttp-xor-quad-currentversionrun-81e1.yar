rule TTP_XOR_QUAD_CurrentVersionRun_81e1 {
  strings:
    $key_81e1 = { d2 8e [2] f6 80 [2] dd ac [2] f3 8e [2] e7 95 [2] e8 8f [2] f6 92 [2] f4 93 [2] ef 95 [2] f3 92 [2] ef bd }

  condition:
    any of them
}