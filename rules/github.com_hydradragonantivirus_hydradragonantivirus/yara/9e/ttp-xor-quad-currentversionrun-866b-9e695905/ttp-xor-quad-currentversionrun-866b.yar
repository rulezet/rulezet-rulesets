rule TTP_XOR_QUAD_CurrentVersionRun_866b {
  strings:
    $key_866b = { d5 04 [2] f1 0a [2] da 26 [2] f4 04 [2] e0 1f [2] ef 05 [2] f1 18 [2] f3 19 [2] e8 1f [2] f4 18 [2] e8 37 }

  condition:
    any of them
}