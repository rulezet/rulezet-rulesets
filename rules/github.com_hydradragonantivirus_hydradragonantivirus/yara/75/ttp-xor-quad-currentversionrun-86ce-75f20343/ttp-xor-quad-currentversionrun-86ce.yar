rule TTP_XOR_QUAD_CurrentVersionRun_86ce {
  strings:
    $key_86ce = { d5 a1 [2] f1 af [2] da 83 [2] f4 a1 [2] e0 ba [2] ef a0 [2] f1 bd [2] f3 bc [2] e8 ba [2] f4 bd [2] e8 92 }

  condition:
    any of them
}