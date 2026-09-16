rule TTP_XOR_QUAD_CurrentVersionRun_86ee {
  strings:
    $key_86ee = { d5 81 [2] f1 8f [2] da a3 [2] f4 81 [2] e0 9a [2] ef 80 [2] f1 9d [2] f3 9c [2] e8 9a [2] f4 9d [2] e8 b2 }

  condition:
    any of them
}