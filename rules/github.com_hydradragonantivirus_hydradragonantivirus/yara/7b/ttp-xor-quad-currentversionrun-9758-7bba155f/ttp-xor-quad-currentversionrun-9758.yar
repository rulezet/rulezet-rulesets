rule TTP_XOR_QUAD_CurrentVersionRun_9758 {
  strings:
    $key_9758 = { c4 37 [2] e0 39 [2] cb 15 [2] e5 37 [2] f1 2c [2] fe 36 [2] e0 2b [2] e2 2a [2] f9 2c [2] e5 2b [2] f9 04 }

  condition:
    any of them
}