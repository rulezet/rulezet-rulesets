rule TTP_XOR_QUAD_CurrentVersionRun_81ce {
  strings:
    $key_81ce = { d2 a1 [2] f6 af [2] dd 83 [2] f3 a1 [2] e7 ba [2] e8 a0 [2] f6 bd [2] f4 bc [2] ef ba [2] f3 bd [2] ef 92 }

  condition:
    any of them
}