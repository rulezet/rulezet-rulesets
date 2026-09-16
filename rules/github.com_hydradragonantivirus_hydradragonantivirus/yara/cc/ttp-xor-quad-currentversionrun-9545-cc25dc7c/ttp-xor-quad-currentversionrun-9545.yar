rule TTP_XOR_QUAD_CurrentVersionRun_9545 {
  strings:
    $key_9545 = { c6 2a [2] e2 24 [2] c9 08 [2] e7 2a [2] f3 31 [2] fc 2b [2] e2 36 [2] e0 37 [2] fb 31 [2] e7 36 [2] fb 19 }

  condition:
    any of them
}