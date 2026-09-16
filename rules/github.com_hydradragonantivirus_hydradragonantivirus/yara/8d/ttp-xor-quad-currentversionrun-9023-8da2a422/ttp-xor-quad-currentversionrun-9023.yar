rule TTP_XOR_QUAD_CurrentVersionRun_9023 {
  strings:
    $key_9023 = { c3 4c [2] e7 42 [2] cc 6e [2] e2 4c [2] f6 57 [2] f9 4d [2] e7 50 [2] e5 51 [2] fe 57 [2] e2 50 [2] fe 7f }

  condition:
    any of them
}