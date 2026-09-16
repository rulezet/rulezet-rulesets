rule TTP_XOR_QUAD_CurrentVersionRun_9248 {
  strings:
    $key_9248 = { c1 27 [2] e5 29 [2] ce 05 [2] e0 27 [2] f4 3c [2] fb 26 [2] e5 3b [2] e7 3a [2] fc 3c [2] e0 3b [2] fc 14 }

  condition:
    any of them
}