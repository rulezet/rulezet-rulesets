rule TTP_XOR_QUAD_CurrentVersionRun_9266 {
  strings:
    $key_9266 = { c1 09 [2] e5 07 [2] ce 2b [2] e0 09 [2] f4 12 [2] fb 08 [2] e5 15 [2] e7 14 [2] fc 12 [2] e0 15 [2] fc 3a }

  condition:
    any of them
}