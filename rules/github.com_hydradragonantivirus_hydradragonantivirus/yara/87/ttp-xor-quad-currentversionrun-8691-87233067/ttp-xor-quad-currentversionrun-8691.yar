rule TTP_XOR_QUAD_CurrentVersionRun_8691 {
  strings:
    $key_8691 = { d5 fe [2] f1 f0 [2] da dc [2] f4 fe [2] e0 e5 [2] ef ff [2] f1 e2 [2] f3 e3 [2] e8 e5 [2] f4 e2 [2] e8 cd }

  condition:
    any of them
}