rule TTP_XOR_QUAD_CurrentVersionRun_860a {
  strings:
    $key_860a = { d5 65 [2] f1 6b [2] da 47 [2] f4 65 [2] e0 7e [2] ef 64 [2] f1 79 [2] f3 78 [2] e8 7e [2] f4 79 [2] e8 56 }

  condition:
    any of them
}