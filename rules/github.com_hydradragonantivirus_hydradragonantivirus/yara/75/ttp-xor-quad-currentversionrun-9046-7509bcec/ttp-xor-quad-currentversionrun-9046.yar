rule TTP_XOR_QUAD_CurrentVersionRun_9046 {
  strings:
    $key_9046 = { c3 29 [2] e7 27 [2] cc 0b [2] e2 29 [2] f6 32 [2] f9 28 [2] e7 35 [2] e5 34 [2] fe 32 [2] e2 35 [2] fe 1a }

  condition:
    any of them
}