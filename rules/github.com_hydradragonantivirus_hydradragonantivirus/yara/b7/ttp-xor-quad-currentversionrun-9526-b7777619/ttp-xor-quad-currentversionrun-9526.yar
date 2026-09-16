rule TTP_XOR_QUAD_CurrentVersionRun_9526 {
  strings:
    $key_9526 = { c6 49 [2] e2 47 [2] c9 6b [2] e7 49 [2] f3 52 [2] fc 48 [2] e2 55 [2] e0 54 [2] fb 52 [2] e7 55 [2] fb 7a }

  condition:
    any of them
}