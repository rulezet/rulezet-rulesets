rule TTP_XOR_QUAD_CurrentVersionRun_9563 {
  strings:
    $key_9563 = { c6 0c [2] e2 02 [2] c9 2e [2] e7 0c [2] f3 17 [2] fc 0d [2] e2 10 [2] e0 11 [2] fb 17 [2] e7 10 [2] fb 3f }

  condition:
    any of them
}