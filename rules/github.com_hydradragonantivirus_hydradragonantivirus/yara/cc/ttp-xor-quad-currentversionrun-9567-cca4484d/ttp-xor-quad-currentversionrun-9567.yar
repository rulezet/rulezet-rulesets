rule TTP_XOR_QUAD_CurrentVersionRun_9567 {
  strings:
    $key_9567 = { c6 08 [2] e2 06 [2] c9 2a [2] e7 08 [2] f3 13 [2] fc 09 [2] e2 14 [2] e0 15 [2] fb 13 [2] e7 14 [2] fb 3b }

  condition:
    any of them
}