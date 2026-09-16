rule TTP_XOR_QUAD_CurrentVersionRun_9748 {
  strings:
    $key_9748 = { c4 27 [2] e0 29 [2] cb 05 [2] e5 27 [2] f1 3c [2] fe 26 [2] e0 3b [2] e2 3a [2] f9 3c [2] e5 3b [2] f9 14 }

  condition:
    any of them
}