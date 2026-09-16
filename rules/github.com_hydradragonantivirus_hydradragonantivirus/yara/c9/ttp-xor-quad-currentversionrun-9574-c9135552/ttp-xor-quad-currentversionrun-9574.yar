rule TTP_XOR_QUAD_CurrentVersionRun_9574 {
  strings:
    $key_9574 = { c6 1b [2] e2 15 [2] c9 39 [2] e7 1b [2] f3 00 [2] fc 1a [2] e2 07 [2] e0 06 [2] fb 00 [2] e7 07 [2] fb 28 }

  condition:
    any of them
}