rule TTP_XOR_QUAD_CurrentVersionRun_9332 {
  strings:
    $key_9332 = { c0 5d [2] e4 53 [2] cf 7f [2] e1 5d [2] f5 46 [2] fa 5c [2] e4 41 [2] e6 40 [2] fd 46 [2] e1 41 [2] fd 6e }

  condition:
    any of them
}