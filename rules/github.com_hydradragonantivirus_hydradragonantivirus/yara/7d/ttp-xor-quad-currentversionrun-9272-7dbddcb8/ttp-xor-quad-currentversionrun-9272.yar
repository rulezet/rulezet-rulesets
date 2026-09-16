rule TTP_XOR_QUAD_CurrentVersionRun_9272 {
  strings:
    $key_9272 = { c1 1d [2] e5 13 [2] ce 3f [2] e0 1d [2] f4 06 [2] fb 1c [2] e5 01 [2] e7 00 [2] fc 06 [2] e0 01 [2] fc 2e }

  condition:
    any of them
}