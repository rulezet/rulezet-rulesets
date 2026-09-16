rule TTP_XOR_QUAD_CurrentVersionRun_9461 {
  strings:
    $key_9461 = { c7 0e [2] e3 00 [2] c8 2c [2] e6 0e [2] f2 15 [2] fd 0f [2] e3 12 [2] e1 13 [2] fa 15 [2] e6 12 [2] fa 3d }

  condition:
    any of them
}