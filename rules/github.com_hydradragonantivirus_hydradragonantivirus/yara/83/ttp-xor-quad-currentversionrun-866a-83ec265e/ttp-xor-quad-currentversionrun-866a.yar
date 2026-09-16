rule TTP_XOR_QUAD_CurrentVersionRun_866a {
  strings:
    $key_866a = { d5 05 [2] f1 0b [2] da 27 [2] f4 05 [2] e0 1e [2] ef 04 [2] f1 19 [2] f3 18 [2] e8 1e [2] f4 19 [2] e8 36 }

  condition:
    any of them
}