rule TTP_XOR_QUAD_CurrentVersionRun_81fd {
  strings:
    $key_81fd = { d2 92 [2] f6 9c [2] dd b0 [2] f3 92 [2] e7 89 [2] e8 93 [2] f6 8e [2] f4 8f [2] ef 89 [2] f3 8e [2] ef a1 }

  condition:
    any of them
}