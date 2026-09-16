rule TTP_XOR_QUAD_CurrentVersionRun_9247 {
  strings:
    $key_9247 = { c1 28 [2] e5 26 [2] ce 0a [2] e0 28 [2] f4 33 [2] fb 29 [2] e5 34 [2] e7 35 [2] fc 33 [2] e0 34 [2] fc 1b }

  condition:
    any of them
}