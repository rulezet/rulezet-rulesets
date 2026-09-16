rule TTP_XOR_QUAD_CurrentVersionRun_9765 {
  strings:
    $key_9765 = { c4 0a [2] e0 04 [2] cb 28 [2] e5 0a [2] f1 11 [2] fe 0b [2] e0 16 [2] e2 17 [2] f9 11 [2] e5 16 [2] f9 39 }

  condition:
    any of them
}