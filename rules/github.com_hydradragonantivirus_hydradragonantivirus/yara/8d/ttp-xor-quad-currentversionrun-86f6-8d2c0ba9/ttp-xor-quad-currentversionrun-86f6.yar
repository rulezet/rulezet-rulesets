rule TTP_XOR_QUAD_CurrentVersionRun_86f6 {
  strings:
    $key_86f6 = { d5 99 [2] f1 97 [2] da bb [2] f4 99 [2] e0 82 [2] ef 98 [2] f1 85 [2] f3 84 [2] e8 82 [2] f4 85 [2] e8 aa }

  condition:
    any of them
}