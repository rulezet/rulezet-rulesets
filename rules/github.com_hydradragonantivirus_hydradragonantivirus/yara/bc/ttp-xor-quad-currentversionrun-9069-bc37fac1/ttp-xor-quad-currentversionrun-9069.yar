rule TTP_XOR_QUAD_CurrentVersionRun_9069 {
  strings:
    $key_9069 = { c3 06 [2] e7 08 [2] cc 24 [2] e2 06 [2] f6 1d [2] f9 07 [2] e7 1a [2] e5 1b [2] fe 1d [2] e2 1a [2] fe 35 }

  condition:
    any of them
}