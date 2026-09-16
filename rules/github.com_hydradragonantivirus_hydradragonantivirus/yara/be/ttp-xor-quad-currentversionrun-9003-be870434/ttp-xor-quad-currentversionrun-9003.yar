rule TTP_XOR_QUAD_CurrentVersionRun_9003 {
  strings:
    $key_9003 = { c3 6c [2] e7 62 [2] cc 4e [2] e2 6c [2] f6 77 [2] f9 6d [2] e7 70 [2] e5 71 [2] fe 77 [2] e2 70 [2] fe 5f }

  condition:
    any of them
}