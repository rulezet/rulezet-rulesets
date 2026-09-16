rule TTP_XOR_QUAD_CurrentVersionRun_86fc {
  strings:
    $key_86fc = { d5 93 [2] f1 9d [2] da b1 [2] f4 93 [2] e0 88 [2] ef 92 [2] f1 8f [2] f3 8e [2] e8 88 [2] f4 8f [2] e8 a0 }

  condition:
    any of them
}