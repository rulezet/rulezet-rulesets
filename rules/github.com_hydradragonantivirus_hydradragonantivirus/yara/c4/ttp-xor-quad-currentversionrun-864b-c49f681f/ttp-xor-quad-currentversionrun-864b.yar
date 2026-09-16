rule TTP_XOR_QUAD_CurrentVersionRun_864b {
  strings:
    $key_864b = { d5 24 [2] f1 2a [2] da 06 [2] f4 24 [2] e0 3f [2] ef 25 [2] f1 38 [2] f3 39 [2] e8 3f [2] f4 38 [2] e8 17 }

  condition:
    any of them
}