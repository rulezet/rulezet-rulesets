rule TTP_XOR_QUAD_CurrentVersionRun_9750 {
  strings:
    $key_9750 = { c4 3f [2] e0 31 [2] cb 1d [2] e5 3f [2] f1 24 [2] fe 3e [2] e0 23 [2] e2 22 [2] f9 24 [2] e5 23 [2] f9 0c }

  condition:
    any of them
}