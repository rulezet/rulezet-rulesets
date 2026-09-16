rule TTP_XOR_QUAD_CurrentVersionRun_9555 {
  strings:
    $key_9555 = { c6 3a [2] e2 34 [2] c9 18 [2] e7 3a [2] f3 21 [2] fc 3b [2] e2 26 [2] e0 27 [2] fb 21 [2] e7 26 [2] fb 09 }

  condition:
    any of them
}