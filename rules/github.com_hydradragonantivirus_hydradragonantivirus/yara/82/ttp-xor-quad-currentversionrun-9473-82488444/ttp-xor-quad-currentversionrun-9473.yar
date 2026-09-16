rule TTP_XOR_QUAD_CurrentVersionRun_9473 {
  strings:
    $key_9473 = { c7 1c [2] e3 12 [2] c8 3e [2] e6 1c [2] f2 07 [2] fd 1d [2] e3 00 [2] e1 01 [2] fa 07 [2] e6 00 [2] fa 2f }

  condition:
    any of them
}