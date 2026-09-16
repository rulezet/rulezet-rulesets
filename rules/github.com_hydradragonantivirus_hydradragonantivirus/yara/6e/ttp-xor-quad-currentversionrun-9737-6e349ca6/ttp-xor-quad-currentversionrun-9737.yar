rule TTP_XOR_QUAD_CurrentVersionRun_9737 {
  strings:
    $key_9737 = { c4 58 [2] e0 56 [2] cb 7a [2] e5 58 [2] f1 43 [2] fe 59 [2] e0 44 [2] e2 45 [2] f9 43 [2] e5 44 [2] f9 6b }

  condition:
    any of them
}