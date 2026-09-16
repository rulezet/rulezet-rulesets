rule TTP_XOR_QUAD_CurrentVersionRun_9756 {
  strings:
    $key_9756 = { c4 39 [2] e0 37 [2] cb 1b [2] e5 39 [2] f1 22 [2] fe 38 [2] e0 25 [2] e2 24 [2] f9 22 [2] e5 25 [2] f9 0a }

  condition:
    any of them
}