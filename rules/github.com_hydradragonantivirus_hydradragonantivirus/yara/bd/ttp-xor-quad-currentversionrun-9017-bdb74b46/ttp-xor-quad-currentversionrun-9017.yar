rule TTP_XOR_QUAD_CurrentVersionRun_9017 {
  strings:
    $key_9017 = { c3 78 [2] e7 76 [2] cc 5a [2] e2 78 [2] f6 63 [2] f9 79 [2] e7 64 [2] e5 65 [2] fe 63 [2] e2 64 [2] fe 4b }

  condition:
    any of them
}