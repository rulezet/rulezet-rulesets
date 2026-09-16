rule TTP_XOR_QUAD_CurrentVersionRun_866e {
  strings:
    $key_866e = { d5 01 [2] f1 0f [2] da 23 [2] f4 01 [2] e0 1a [2] ef 00 [2] f1 1d [2] f3 1c [2] e8 1a [2] f4 1d [2] e8 32 }

  condition:
    any of them
}