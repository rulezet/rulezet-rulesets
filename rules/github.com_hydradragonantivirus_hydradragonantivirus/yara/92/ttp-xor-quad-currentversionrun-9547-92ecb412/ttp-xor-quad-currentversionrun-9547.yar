rule TTP_XOR_QUAD_CurrentVersionRun_9547 {
  strings:
    $key_9547 = { c6 28 [2] e2 26 [2] c9 0a [2] e7 28 [2] f3 33 [2] fc 29 [2] e2 34 [2] e0 35 [2] fb 33 [2] e7 34 [2] fb 1b }

  condition:
    any of them
}