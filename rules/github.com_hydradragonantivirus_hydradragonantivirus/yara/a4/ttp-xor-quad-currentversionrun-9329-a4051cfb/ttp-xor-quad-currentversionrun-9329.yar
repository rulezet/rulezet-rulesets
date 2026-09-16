rule TTP_XOR_QUAD_CurrentVersionRun_9329 {
  strings:
    $key_9329 = { c0 46 [2] e4 48 [2] cf 64 [2] e1 46 [2] f5 5d [2] fa 47 [2] e4 5a [2] e6 5b [2] fd 5d [2] e1 5a [2] fd 75 }

  condition:
    any of them
}