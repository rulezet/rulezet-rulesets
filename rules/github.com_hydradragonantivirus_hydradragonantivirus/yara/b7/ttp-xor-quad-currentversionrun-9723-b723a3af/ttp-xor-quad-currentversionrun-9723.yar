rule TTP_XOR_QUAD_CurrentVersionRun_9723 {
  strings:
    $key_9723 = { c4 4c [2] e0 42 [2] cb 6e [2] e5 4c [2] f1 57 [2] fe 4d [2] e0 50 [2] e2 51 [2] f9 57 [2] e5 50 [2] f9 7f }

  condition:
    any of them
}