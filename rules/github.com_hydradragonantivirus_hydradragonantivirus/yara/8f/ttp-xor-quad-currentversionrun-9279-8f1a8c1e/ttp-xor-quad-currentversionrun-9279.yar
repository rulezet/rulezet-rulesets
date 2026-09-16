rule TTP_XOR_QUAD_CurrentVersionRun_9279 {
  strings:
    $key_9279 = { c1 16 [2] e5 18 [2] ce 34 [2] e0 16 [2] f4 0d [2] fb 17 [2] e5 0a [2] e7 0b [2] fc 0d [2] e0 0a [2] fc 25 }

  condition:
    any of them
}