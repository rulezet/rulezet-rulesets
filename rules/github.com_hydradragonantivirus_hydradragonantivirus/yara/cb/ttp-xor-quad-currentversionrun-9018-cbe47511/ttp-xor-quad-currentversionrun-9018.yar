rule TTP_XOR_QUAD_CurrentVersionRun_9018 {
  strings:
    $key_9018 = { c3 77 [2] e7 79 [2] cc 55 [2] e2 77 [2] f6 6c [2] f9 76 [2] e7 6b [2] e5 6a [2] fe 6c [2] e2 6b [2] fe 44 }

  condition:
    any of them
}