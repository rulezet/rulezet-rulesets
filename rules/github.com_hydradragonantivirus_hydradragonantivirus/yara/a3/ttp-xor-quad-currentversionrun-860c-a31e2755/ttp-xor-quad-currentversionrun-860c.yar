rule TTP_XOR_QUAD_CurrentVersionRun_860c {
  strings:
    $key_860c = { d5 63 [2] f1 6d [2] da 41 [2] f4 63 [2] e0 78 [2] ef 62 [2] f1 7f [2] f3 7e [2] e8 78 [2] f4 7f [2] e8 50 }

  condition:
    any of them
}