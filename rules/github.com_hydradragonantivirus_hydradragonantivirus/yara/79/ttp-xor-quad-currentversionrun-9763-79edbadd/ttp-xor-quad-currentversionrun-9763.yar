rule TTP_XOR_QUAD_CurrentVersionRun_9763 {
  strings:
    $key_9763 = { c4 0c [2] e0 02 [2] cb 2e [2] e5 0c [2] f1 17 [2] fe 0d [2] e0 10 [2] e2 11 [2] f9 17 [2] e5 10 [2] f9 3f }

  condition:
    any of them
}