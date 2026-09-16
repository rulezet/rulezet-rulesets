rule TTP_XOR_QUAD_CurrentVersionRun_8573 {
  strings:
    $key_8573 = { d6 1c [2] f2 12 [2] d9 3e [2] f7 1c [2] e3 07 [2] ec 1d [2] f2 00 [2] f0 01 [2] eb 07 [2] f7 00 [2] eb 2f }

  condition:
    any of them
}