rule TTP_XOR_QUAD_CurrentVersionRun_9258 {
  strings:
    $key_9258 = { c1 37 [2] e5 39 [2] ce 15 [2] e0 37 [2] f4 2c [2] fb 36 [2] e5 2b [2] e7 2a [2] fc 2c [2] e0 2b [2] fc 04 }

  condition:
    any of them
}