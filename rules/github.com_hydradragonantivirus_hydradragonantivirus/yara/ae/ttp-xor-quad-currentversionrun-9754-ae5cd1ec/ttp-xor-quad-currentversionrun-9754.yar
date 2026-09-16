rule TTP_XOR_QUAD_CurrentVersionRun_9754 {
  strings:
    $key_9754 = { c4 3b [2] e0 35 [2] cb 19 [2] e5 3b [2] f1 20 [2] fe 3a [2] e0 27 [2] e2 26 [2] f9 20 [2] e5 27 [2] f9 08 }

  condition:
    any of them
}