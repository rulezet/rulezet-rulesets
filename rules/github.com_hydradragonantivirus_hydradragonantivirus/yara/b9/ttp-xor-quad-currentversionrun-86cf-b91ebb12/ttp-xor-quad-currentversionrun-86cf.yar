rule TTP_XOR_QUAD_CurrentVersionRun_86cf {
  strings:
    $key_86cf = { d5 a0 [2] f1 ae [2] da 82 [2] f4 a0 [2] e0 bb [2] ef a1 [2] f1 bc [2] f3 bd [2] e8 bb [2] f4 bc [2] e8 93 }

  condition:
    any of them
}