rule TTP_XOR_QUAD_CurrentVersionRun_9066 {
  strings:
    $key_9066 = { c3 09 [2] e7 07 [2] cc 2b [2] e2 09 [2] f6 12 [2] f9 08 [2] e7 15 [2] e5 14 [2] fe 12 [2] e2 15 [2] fe 3a }

  condition:
    any of them
}