rule TTP_XOR_QUAD_CurrentVersionRun_9751 {
  strings:
    $key_9751 = { c4 3e [2] e0 30 [2] cb 1c [2] e5 3e [2] f1 25 [2] fe 3f [2] e0 22 [2] e2 23 [2] f9 25 [2] e5 22 [2] f9 0d }

  condition:
    any of them
}