rule TTP_XOR_QUAD_CurrentVersionRun_9544 {
  strings:
    $key_9544 = { c6 2b [2] e2 25 [2] c9 09 [2] e7 2b [2] f3 30 [2] fc 2a [2] e2 37 [2] e0 36 [2] fb 30 [2] e7 37 [2] fb 18 }

  condition:
    any of them
}