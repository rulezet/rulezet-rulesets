rule TTP_XOR_QUAD_CurrentVersionRun_9775 {
  strings:
    $key_9775 = { c4 1a [2] e0 14 [2] cb 38 [2] e5 1a [2] f1 01 [2] fe 1b [2] e0 06 [2] e2 07 [2] f9 01 [2] e5 06 [2] f9 29 }

  condition:
    any of them
}