rule TTP_XOR_QUAD_CurrentVersionRun_9344 {
  strings:
    $key_9344 = { c0 2b [2] e4 25 [2] cf 09 [2] e1 2b [2] f5 30 [2] fa 2a [2] e4 37 [2] e6 36 [2] fd 30 [2] e1 37 [2] fd 18 }

  condition:
    any of them
}