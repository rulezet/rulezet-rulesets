rule TTP_XOR_QUAD_CurrentVersionRun_9527 {
  strings:
    $key_9527 = { c6 48 [2] e2 46 [2] c9 6a [2] e7 48 [2] f3 53 [2] fc 49 [2] e2 54 [2] e0 55 [2] fb 53 [2] e7 54 [2] fb 7b }

  condition:
    any of them
}