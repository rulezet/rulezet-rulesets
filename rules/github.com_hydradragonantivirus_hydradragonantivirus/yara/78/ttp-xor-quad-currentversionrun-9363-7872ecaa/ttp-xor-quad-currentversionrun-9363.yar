rule TTP_XOR_QUAD_CurrentVersionRun_9363 {
  strings:
    $key_9363 = { c0 0c [2] e4 02 [2] cf 2e [2] e1 0c [2] f5 17 [2] fa 0d [2] e4 10 [2] e6 11 [2] fd 17 [2] e1 10 [2] fd 3f }

  condition:
    any of them
}