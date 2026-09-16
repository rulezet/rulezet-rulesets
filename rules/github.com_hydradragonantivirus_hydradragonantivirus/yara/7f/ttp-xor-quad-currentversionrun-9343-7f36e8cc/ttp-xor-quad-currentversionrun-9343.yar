rule TTP_XOR_QUAD_CurrentVersionRun_9343 {
  strings:
    $key_9343 = { c0 2c [2] e4 22 [2] cf 0e [2] e1 2c [2] f5 37 [2] fa 2d [2] e4 30 [2] e6 31 [2] fd 37 [2] e1 30 [2] fd 1f }

  condition:
    any of them
}