rule TTP_XOR_QUAD_CurrentVersionRun_9075 {
  strings:
    $key_9075 = { c3 1a [2] e7 14 [2] cc 38 [2] e2 1a [2] f6 01 [2] f9 1b [2] e7 06 [2] e5 07 [2] fe 01 [2] e2 06 [2] fe 29 }

  condition:
    any of them
}