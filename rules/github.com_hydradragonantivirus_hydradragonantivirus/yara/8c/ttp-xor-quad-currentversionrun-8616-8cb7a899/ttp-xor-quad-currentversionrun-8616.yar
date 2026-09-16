rule TTP_XOR_QUAD_CurrentVersionRun_8616 {
  strings:
    $key_8616 = { d5 79 [2] f1 77 [2] da 5b [2] f4 79 [2] e0 62 [2] ef 78 [2] f1 65 [2] f3 64 [2] e8 62 [2] f4 65 [2] e8 4a }

  condition:
    any of them
}