rule TTP_XOR_QUAD_CurrentVersionRun_9059 {
  strings:
    $key_9059 = { c3 36 [2] e7 38 [2] cc 14 [2] e2 36 [2] f6 2d [2] f9 37 [2] e7 2a [2] e5 2b [2] fe 2d [2] e2 2a [2] fe 05 }

  condition:
    any of them
}