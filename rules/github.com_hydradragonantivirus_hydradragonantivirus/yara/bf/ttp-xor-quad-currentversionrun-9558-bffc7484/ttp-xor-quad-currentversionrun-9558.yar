rule TTP_XOR_QUAD_CurrentVersionRun_9558 {
  strings:
    $key_9558 = { c6 37 [2] e2 39 [2] c9 15 [2] e7 37 [2] f3 2c [2] fc 36 [2] e2 2b [2] e0 2a [2] fb 2c [2] e7 2b [2] fb 04 }

  condition:
    any of them
}