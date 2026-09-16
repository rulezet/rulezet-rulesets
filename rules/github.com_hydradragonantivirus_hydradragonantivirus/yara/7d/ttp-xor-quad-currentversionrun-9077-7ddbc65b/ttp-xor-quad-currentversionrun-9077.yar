rule TTP_XOR_QUAD_CurrentVersionRun_9077 {
  strings:
    $key_9077 = { c3 18 [2] e7 16 [2] cc 3a [2] e2 18 [2] f6 03 [2] f9 19 [2] e7 04 [2] e5 05 [2] fe 03 [2] e2 04 [2] fe 2b }

  condition:
    any of them
}