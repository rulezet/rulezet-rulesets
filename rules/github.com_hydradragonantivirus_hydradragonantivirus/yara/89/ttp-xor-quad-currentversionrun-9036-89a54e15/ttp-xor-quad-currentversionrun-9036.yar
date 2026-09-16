rule TTP_XOR_QUAD_CurrentVersionRun_9036 {
  strings:
    $key_9036 = { c3 59 [2] e7 57 [2] cc 7b [2] e2 59 [2] f6 42 [2] f9 58 [2] e7 45 [2] e5 44 [2] fe 42 [2] e2 45 [2] fe 6a }

  condition:
    any of them
}