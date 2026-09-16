rule TTP_XOR_QUAD_CurrentVersionRun_9242 {
  strings:
    $key_9242 = { c1 2d [2] e5 23 [2] ce 0f [2] e0 2d [2] f4 36 [2] fb 2c [2] e5 31 [2] e7 30 [2] fc 36 [2] e0 31 [2] fc 1e }

  condition:
    any of them
}