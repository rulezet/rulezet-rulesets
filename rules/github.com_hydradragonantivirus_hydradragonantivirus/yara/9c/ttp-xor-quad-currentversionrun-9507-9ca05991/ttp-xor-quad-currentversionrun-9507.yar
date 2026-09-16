rule TTP_XOR_QUAD_CurrentVersionRun_9507 {
  strings:
    $key_9507 = { c6 68 [2] e2 66 [2] c9 4a [2] e7 68 [2] f3 73 [2] fc 69 [2] e2 74 [2] e0 75 [2] fb 73 [2] e7 74 [2] fb 5b }

  condition:
    any of them
}