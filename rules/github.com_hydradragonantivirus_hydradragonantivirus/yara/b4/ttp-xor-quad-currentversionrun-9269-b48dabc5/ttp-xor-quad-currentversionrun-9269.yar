rule TTP_XOR_QUAD_CurrentVersionRun_9269 {
  strings:
    $key_9269 = { c1 06 [2] e5 08 [2] ce 24 [2] e0 06 [2] f4 1d [2] fb 07 [2] e5 1a [2] e7 1b [2] fc 1d [2] e0 1a [2] fc 35 }

  condition:
    any of them
}