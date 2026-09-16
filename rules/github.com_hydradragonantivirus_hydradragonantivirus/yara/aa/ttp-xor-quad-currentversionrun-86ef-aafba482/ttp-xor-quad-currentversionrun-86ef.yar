rule TTP_XOR_QUAD_CurrentVersionRun_86ef {
  strings:
    $key_86ef = { d5 80 [2] f1 8e [2] da a2 [2] f4 80 [2] e0 9b [2] ef 81 [2] f1 9c [2] f3 9d [2] e8 9b [2] f4 9c [2] e8 b3 }

  condition:
    any of them
}