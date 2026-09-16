rule TTP_XOR_QUAD_CurrentVersionRun_8253 {
  strings:
    $key_8253 = { d1 3c [2] f5 32 [2] de 1e [2] f0 3c [2] e4 27 [2] eb 3d [2] f5 20 [2] f7 21 [2] ec 27 [2] f0 20 [2] ec 0f }

  condition:
    any of them
}