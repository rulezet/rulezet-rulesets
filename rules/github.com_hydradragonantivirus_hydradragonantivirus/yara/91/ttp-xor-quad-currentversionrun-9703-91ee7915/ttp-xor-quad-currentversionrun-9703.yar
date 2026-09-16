rule TTP_XOR_QUAD_CurrentVersionRun_9703 {
  strings:
    $key_9703 = { c4 6c [2] e0 62 [2] cb 4e [2] e5 6c [2] f1 77 [2] fe 6d [2] e0 70 [2] e2 71 [2] f9 77 [2] e5 70 [2] f9 5f }

  condition:
    any of them
}