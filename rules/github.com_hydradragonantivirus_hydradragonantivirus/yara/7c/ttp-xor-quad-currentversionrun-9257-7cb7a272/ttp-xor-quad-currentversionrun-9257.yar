rule TTP_XOR_QUAD_CurrentVersionRun_9257 {
  strings:
    $key_9257 = { c1 38 [2] e5 36 [2] ce 1a [2] e0 38 [2] f4 23 [2] fb 39 [2] e5 24 [2] e7 25 [2] fc 23 [2] e0 24 [2] fc 0b }

  condition:
    any of them
}