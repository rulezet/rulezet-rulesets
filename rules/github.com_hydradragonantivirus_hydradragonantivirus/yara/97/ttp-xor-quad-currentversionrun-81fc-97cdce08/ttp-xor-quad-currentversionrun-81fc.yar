rule TTP_XOR_QUAD_CurrentVersionRun_81fc {
  strings:
    $key_81fc = { d2 93 [2] f6 9d [2] dd b1 [2] f3 93 [2] e7 88 [2] e8 92 [2] f6 8f [2] f4 8e [2] ef 88 [2] f3 8f [2] ef a0 }

  condition:
    any of them
}