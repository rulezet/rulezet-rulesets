rule TTP_XOR_QUAD_CurrentVersionRun_9718 {
  strings:
    $key_9718 = { c4 77 [2] e0 79 [2] cb 55 [2] e5 77 [2] f1 6c [2] fe 76 [2] e0 6b [2] e2 6a [2] f9 6c [2] e5 6b [2] f9 44 }

  condition:
    any of them
}