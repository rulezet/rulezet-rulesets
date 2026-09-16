rule TTP_XOR_QUAD_CurrentVersionRun_9442 {
  strings:
    $key_9442 = { c7 2d [2] e3 23 [2] c8 0f [2] e6 2d [2] f2 36 [2] fd 2c [2] e3 31 [2] e1 30 [2] fa 36 [2] e6 31 [2] fa 1e }

  condition:
    any of them
}