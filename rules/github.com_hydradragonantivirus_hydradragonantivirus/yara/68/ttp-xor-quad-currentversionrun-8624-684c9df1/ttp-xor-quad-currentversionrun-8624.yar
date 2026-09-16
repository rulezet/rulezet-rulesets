rule TTP_XOR_QUAD_CurrentVersionRun_8624 {
  strings:
    $key_8624 = { d5 4b [2] f1 45 [2] da 69 [2] f4 4b [2] e0 50 [2] ef 4a [2] f1 57 [2] f3 56 [2] e8 50 [2] f4 57 [2] e8 78 }

  condition:
    any of them
}