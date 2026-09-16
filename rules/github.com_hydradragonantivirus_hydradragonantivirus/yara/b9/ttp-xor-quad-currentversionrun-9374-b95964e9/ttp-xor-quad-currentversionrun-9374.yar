rule TTP_XOR_QUAD_CurrentVersionRun_9374 {
  strings:
    $key_9374 = { c0 1b [2] e4 15 [2] cf 39 [2] e1 1b [2] f5 00 [2] fa 1a [2] e4 07 [2] e6 06 [2] fd 00 [2] e1 07 [2] fd 28 }

  condition:
    any of them
}