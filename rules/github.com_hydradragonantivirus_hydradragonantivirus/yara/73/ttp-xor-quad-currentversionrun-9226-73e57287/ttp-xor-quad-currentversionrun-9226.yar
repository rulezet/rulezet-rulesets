rule TTP_XOR_QUAD_CurrentVersionRun_9226 {
  strings:
    $key_9226 = { c1 49 [2] e5 47 [2] ce 6b [2] e0 49 [2] f4 52 [2] fb 48 [2] e5 55 [2] e7 54 [2] fc 52 [2] e0 55 [2] fc 7a }

  condition:
    any of them
}