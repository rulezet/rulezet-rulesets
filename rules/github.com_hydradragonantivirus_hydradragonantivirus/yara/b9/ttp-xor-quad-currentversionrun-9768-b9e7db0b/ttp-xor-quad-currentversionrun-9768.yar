rule TTP_XOR_QUAD_CurrentVersionRun_9768 {
  strings:
    $key_9768 = { c4 07 [2] e0 09 [2] cb 25 [2] e5 07 [2] f1 1c [2] fe 06 [2] e0 1b [2] e2 1a [2] f9 1c [2] e5 1b [2] f9 34 }

  condition:
    any of them
}