rule TTP_XOR_QUAD_CurrentVersionRun_867f {
  strings:
    $key_867f = { d5 10 [2] f1 1e [2] da 32 [2] f4 10 [2] e0 0b [2] ef 11 [2] f1 0c [2] f3 0d [2] e8 0b [2] f4 0c [2] e8 23 }

  condition:
    any of them
}