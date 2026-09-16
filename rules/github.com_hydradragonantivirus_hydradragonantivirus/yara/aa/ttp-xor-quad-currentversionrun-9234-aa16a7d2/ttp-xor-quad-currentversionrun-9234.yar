rule TTP_XOR_QUAD_CurrentVersionRun_9234 {
  strings:
    $key_9234 = { c1 5b [2] e5 55 [2] ce 79 [2] e0 5b [2] f4 40 [2] fb 5a [2] e5 47 [2] e7 46 [2] fc 40 [2] e0 47 [2] fc 68 }

  condition:
    any of them
}