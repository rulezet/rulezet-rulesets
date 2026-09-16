rule TTP_XOR_QUAD_CurrentVersionRun_9273 {
  strings:
    $key_9273 = { c1 1c [2] e5 12 [2] ce 3e [2] e0 1c [2] f4 07 [2] fb 1d [2] e5 00 [2] e7 01 [2] fc 07 [2] e0 00 [2] fc 2f }

  condition:
    any of them
}