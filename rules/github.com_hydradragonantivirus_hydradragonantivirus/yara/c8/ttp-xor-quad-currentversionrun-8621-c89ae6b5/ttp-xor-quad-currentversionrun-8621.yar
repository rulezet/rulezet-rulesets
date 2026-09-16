rule TTP_XOR_QUAD_CurrentVersionRun_8621 {
  strings:
    $key_8621 = { d5 4e [2] f1 40 [2] da 6c [2] f4 4e [2] e0 55 [2] ef 4f [2] f1 52 [2] f3 53 [2] e8 55 [2] f4 52 [2] e8 7d }

  condition:
    any of them
}