rule TTP_XOR_QUAD_CurrentVersionRun_9566 {
  strings:
    $key_9566 = { c6 09 [2] e2 07 [2] c9 2b [2] e7 09 [2] f3 12 [2] fc 08 [2] e2 15 [2] e0 14 [2] fb 12 [2] e7 15 [2] fb 3a }

  condition:
    any of them
}