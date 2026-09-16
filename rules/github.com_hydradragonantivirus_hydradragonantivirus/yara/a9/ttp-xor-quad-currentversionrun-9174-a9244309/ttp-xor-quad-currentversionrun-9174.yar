rule TTP_XOR_QUAD_CurrentVersionRun_9174 {
  strings:
    $key_9174 = { c2 1b [2] e6 15 [2] cd 39 [2] e3 1b [2] f7 00 [2] f8 1a [2] e6 07 [2] e4 06 [2] ff 00 [2] e3 07 [2] ff 28 }

  condition:
    any of them
}