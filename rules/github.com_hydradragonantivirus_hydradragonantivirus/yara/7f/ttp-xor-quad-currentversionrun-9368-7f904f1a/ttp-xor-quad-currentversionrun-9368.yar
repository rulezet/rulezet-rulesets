rule TTP_XOR_QUAD_CurrentVersionRun_9368 {
  strings:
    $key_9368 = { c0 07 [2] e4 09 [2] cf 25 [2] e1 07 [2] f5 1c [2] fa 06 [2] e4 1b [2] e6 1a [2] fd 1c [2] e1 1b [2] fd 34 }

  condition:
    any of them
}