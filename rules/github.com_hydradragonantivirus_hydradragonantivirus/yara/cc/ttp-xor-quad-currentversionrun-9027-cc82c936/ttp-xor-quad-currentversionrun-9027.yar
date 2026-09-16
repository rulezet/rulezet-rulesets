rule TTP_XOR_QUAD_CurrentVersionRun_9027 {
  strings:
    $key_9027 = { c3 48 [2] e7 46 [2] cc 6a [2] e2 48 [2] f6 53 [2] f9 49 [2] e7 54 [2] e5 55 [2] fe 53 [2] e2 54 [2] fe 7b }

  condition:
    any of them
}