rule TTP_XOR_QUAD_CurrentVersionRun_9045 {
  strings:
    $key_9045 = { c3 2a [2] e7 24 [2] cc 08 [2] e2 2a [2] f6 31 [2] f9 2b [2] e7 36 [2] e5 37 [2] fe 31 [2] e2 36 [2] fe 19 }

  condition:
    any of them
}