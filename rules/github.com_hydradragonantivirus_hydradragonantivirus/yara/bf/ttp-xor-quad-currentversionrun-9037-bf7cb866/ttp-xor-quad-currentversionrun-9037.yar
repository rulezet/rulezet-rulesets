rule TTP_XOR_QUAD_CurrentVersionRun_9037 {
  strings:
    $key_9037 = { c3 58 [2] e7 56 [2] cc 7a [2] e2 58 [2] f6 43 [2] f9 59 [2] e7 44 [2] e5 45 [2] fe 43 [2] e2 44 [2] fe 6b }

  condition:
    any of them
}