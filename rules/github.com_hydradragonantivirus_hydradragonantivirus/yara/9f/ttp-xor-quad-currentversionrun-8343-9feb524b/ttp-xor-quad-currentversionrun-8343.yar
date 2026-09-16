rule TTP_XOR_QUAD_CurrentVersionRun_8343 {
  strings:
    $key_8343 = { d0 2c [2] f4 22 [2] df 0e [2] f1 2c [2] e5 37 [2] ea 2d [2] f4 30 [2] f6 31 [2] ed 37 [2] f1 30 [2] ed 1f }

  condition:
    any of them
}