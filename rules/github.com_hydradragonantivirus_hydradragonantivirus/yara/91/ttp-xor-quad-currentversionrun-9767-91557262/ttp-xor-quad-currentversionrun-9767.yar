rule TTP_XOR_QUAD_CurrentVersionRun_9767 {
  strings:
    $key_9767 = { c4 08 [2] e0 06 [2] cb 2a [2] e5 08 [2] f1 13 [2] fe 09 [2] e0 14 [2] e2 15 [2] f9 13 [2] e5 14 [2] f9 3b }

  condition:
    any of them
}