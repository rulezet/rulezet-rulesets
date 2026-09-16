rule TTP_XOR_QUAD_CurrentVersionRun_866c {
  strings:
    $key_866c = { d5 03 [2] f1 0d [2] da 21 [2] f4 03 [2] e0 18 [2] ef 02 [2] f1 1f [2] f3 1e [2] e8 18 [2] f4 1f [2] e8 30 }

  condition:
    any of them
}