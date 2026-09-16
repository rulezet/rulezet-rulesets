rule TTP_XOR_QUAD_CurrentVersionRun_9755 {
  strings:
    $key_9755 = { c4 3a [2] e0 34 [2] cb 18 [2] e5 3a [2] f1 21 [2] fe 3b [2] e0 26 [2] e2 27 [2] f9 21 [2] e5 26 [2] f9 09 }

  condition:
    any of them
}