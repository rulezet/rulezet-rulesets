rule TTP_XOR_QUAD_CurrentVersionRun_86dd {
  strings:
    $key_86dd = { d5 b2 [2] f1 bc [2] da 90 [2] f4 b2 [2] e0 a9 [2] ef b3 [2] f1 ae [2] f3 af [2] e8 a9 [2] f4 ae [2] e8 81 }

  condition:
    any of them
}