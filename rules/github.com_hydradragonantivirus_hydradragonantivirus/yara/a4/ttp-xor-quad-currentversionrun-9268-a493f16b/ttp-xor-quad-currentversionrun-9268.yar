rule TTP_XOR_QUAD_CurrentVersionRun_9268 {
  strings:
    $key_9268 = { c1 07 [2] e5 09 [2] ce 25 [2] e0 07 [2] f4 1c [2] fb 06 [2] e5 1b [2] e7 1a [2] fc 1c [2] e0 1b [2] fc 34 }

  condition:
    any of them
}