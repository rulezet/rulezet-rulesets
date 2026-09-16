rule TTP_XOR_QUAD_CurrentVersionRun_9771 {
  strings:
    $key_9771 = { c4 1e [2] e0 10 [2] cb 3c [2] e5 1e [2] f1 05 [2] fe 1f [2] e0 02 [2] e2 03 [2] f9 05 [2] e5 02 [2] f9 2d }

  condition:
    any of them
}