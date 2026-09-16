rule TTP_XOR_QUAD_CurrentVersionRun_9243 {
  strings:
    $key_9243 = { c1 2c [2] e5 22 [2] ce 0e [2] e0 2c [2] f4 37 [2] fb 2d [2] e5 30 [2] e7 31 [2] fc 37 [2] e0 30 [2] fc 1f }

  condition:
    any of them
}