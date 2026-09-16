rule TTP_XOR_QUAD_CurrentVersionRun_9778 {
  strings:
    $key_9778 = { c4 17 [2] e0 19 [2] cb 35 [2] e5 17 [2] f1 0c [2] fe 16 [2] e0 0b [2] e2 0a [2] f9 0c [2] e5 0b [2] f9 24 }

  condition:
    any of them
}