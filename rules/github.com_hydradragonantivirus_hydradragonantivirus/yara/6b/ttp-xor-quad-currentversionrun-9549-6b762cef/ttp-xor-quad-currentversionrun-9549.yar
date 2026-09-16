rule TTP_XOR_QUAD_CurrentVersionRun_9549 {
  strings:
    $key_9549 = { c6 26 [2] e2 28 [2] c9 04 [2] e7 26 [2] f3 3d [2] fc 27 [2] e2 3a [2] e0 3b [2] fb 3d [2] e7 3a [2] fb 15 }

  condition:
    any of them
}