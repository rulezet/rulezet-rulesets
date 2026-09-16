rule TTP_XOR_QUAD_CurrentVersionRun_860f {
  strings:
    $key_860f = { d5 60 [2] f1 6e [2] da 42 [2] f4 60 [2] e0 7b [2] ef 61 [2] f1 7c [2] f3 7d [2] e8 7b [2] f4 7c [2] e8 53 }

  condition:
    any of them
}