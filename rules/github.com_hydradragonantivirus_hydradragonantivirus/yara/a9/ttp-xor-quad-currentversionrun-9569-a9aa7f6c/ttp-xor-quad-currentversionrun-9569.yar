rule TTP_XOR_QUAD_CurrentVersionRun_9569 {
  strings:
    $key_9569 = { c6 06 [2] e2 08 [2] c9 24 [2] e7 06 [2] f3 1d [2] fc 07 [2] e2 1a [2] e0 1b [2] fb 1d [2] e7 1a [2] fb 35 }

  condition:
    any of them
}