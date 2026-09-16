rule TTP_XOR_QUAD_CurrentVersionRun_8653 {
  strings:
    $key_8653 = { d5 3c [2] f1 32 [2] da 1e [2] f4 3c [2] e0 27 [2] ef 3d [2] f1 20 [2] f3 21 [2] e8 27 [2] f4 20 [2] e8 0f }

  condition:
    any of them
}