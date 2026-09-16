rule TTP_XOR_QUAD_CurrentVersionRun_9245 {
  strings:
    $key_9245 = { c1 2a [2] e5 24 [2] ce 08 [2] e0 2a [2] f4 31 [2] fb 2b [2] e5 36 [2] e7 37 [2] fc 31 [2] e0 36 [2] fc 19 }

  condition:
    any of them
}