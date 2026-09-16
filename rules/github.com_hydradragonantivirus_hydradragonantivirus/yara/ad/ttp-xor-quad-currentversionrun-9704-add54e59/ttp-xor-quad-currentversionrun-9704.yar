rule TTP_XOR_QUAD_CurrentVersionRun_9704 {
  strings:
    $key_9704 = { c4 6b [2] e0 65 [2] cb 49 [2] e5 6b [2] f1 70 [2] fe 6a [2] e0 77 [2] e2 76 [2] f9 70 [2] e5 77 [2] f9 58 }

  condition:
    any of them
}