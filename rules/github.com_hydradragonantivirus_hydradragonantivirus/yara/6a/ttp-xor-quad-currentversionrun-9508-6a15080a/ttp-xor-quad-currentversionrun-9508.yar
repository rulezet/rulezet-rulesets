rule TTP_XOR_QUAD_CurrentVersionRun_9508 {
  strings:
    $key_9508 = { c6 67 [2] e2 69 [2] c9 45 [2] e7 67 [2] f3 7c [2] fc 66 [2] e2 7b [2] e0 7a [2] fb 7c [2] e7 7b [2] fb 54 }

  condition:
    any of them
}