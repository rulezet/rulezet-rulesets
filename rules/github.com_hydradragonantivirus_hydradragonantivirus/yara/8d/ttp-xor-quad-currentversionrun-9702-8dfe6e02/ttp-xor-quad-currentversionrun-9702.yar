rule TTP_XOR_QUAD_CurrentVersionRun_9702 {
  strings:
    $key_9702 = { c4 6d [2] e0 63 [2] cb 4f [2] e5 6d [2] f1 76 [2] fe 6c [2] e0 71 [2] e2 70 [2] f9 76 [2] e5 71 [2] f9 5e }

  condition:
    any of them
}