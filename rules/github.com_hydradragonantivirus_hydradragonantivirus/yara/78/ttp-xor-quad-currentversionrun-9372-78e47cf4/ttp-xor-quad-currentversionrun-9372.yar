rule TTP_XOR_QUAD_CurrentVersionRun_9372 {
  strings:
    $key_9372 = { c0 1d [2] e4 13 [2] cf 3f [2] e1 1d [2] f5 06 [2] fa 1c [2] e4 01 [2] e6 00 [2] fd 06 [2] e1 01 [2] fd 2e }

  condition:
    any of them
}