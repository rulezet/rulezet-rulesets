rule TTP_XOR_QUAD_CurrentVersionRun_81dd {
  strings:
    $key_81dd = { d2 b2 [2] f6 bc [2] dd 90 [2] f3 b2 [2] e7 a9 [2] e8 b3 [2] f6 ae [2] f4 af [2] ef a9 [2] f3 ae [2] ef 81 }

  condition:
    any of them
}