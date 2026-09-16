rule TTP_XOR_QUAD_CurrentVersionRun_96c0 {
  strings:
    $key_96c0 = { c5 af [2] e1 a1 [2] ca 8d [2] e4 af [2] f0 b4 [2] ff ae [2] e1 b3 [2] e3 b2 [2] f8 b4 [2] e4 b3 [2] f8 9c }

  condition:
    any of them
}