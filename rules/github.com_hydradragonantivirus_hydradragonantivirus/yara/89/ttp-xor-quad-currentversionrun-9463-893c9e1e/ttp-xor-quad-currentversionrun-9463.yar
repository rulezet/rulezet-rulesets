rule TTP_XOR_QUAD_CurrentVersionRun_9463 {
  strings:
    $key_9463 = { c7 0c [2] e3 02 [2] c8 2e [2] e6 0c [2] f2 17 [2] fd 0d [2] e3 10 [2] e1 11 [2] fa 17 [2] e6 10 [2] fa 3f }

  condition:
    any of them
}