rule TTP_XOR_QUAD_CurrentVersionRun_9267 {
  strings:
    $key_9267 = { c1 08 [2] e5 06 [2] ce 2a [2] e0 08 [2] f4 13 [2] fb 09 [2] e5 14 [2] e7 15 [2] fc 13 [2] e0 14 [2] fc 3b }

  condition:
    any of them
}