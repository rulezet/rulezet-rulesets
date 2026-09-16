rule TTP_XOR_QUAD_CurrentVersionRun_9264 {
  strings:
    $key_9264 = { c1 0b [2] e5 05 [2] ce 29 [2] e0 0b [2] f4 10 [2] fb 0a [2] e5 17 [2] e7 16 [2] fc 10 [2] e0 17 [2] fc 38 }

  condition:
    any of them
}