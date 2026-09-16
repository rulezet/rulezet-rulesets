rule TTP_XOR_QUAD_CurrentVersionRun_9255 {
  strings:
    $key_9255 = { c1 3a [2] e5 34 [2] ce 18 [2] e0 3a [2] f4 21 [2] fb 3b [2] e5 26 [2] e7 27 [2] fc 21 [2] e0 26 [2] fc 09 }

  condition:
    any of them
}