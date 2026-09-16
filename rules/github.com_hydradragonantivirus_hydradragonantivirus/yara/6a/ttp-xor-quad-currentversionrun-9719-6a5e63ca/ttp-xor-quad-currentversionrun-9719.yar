rule TTP_XOR_QUAD_CurrentVersionRun_9719 {
  strings:
    $key_9719 = { c4 76 [2] e0 78 [2] cb 54 [2] e5 76 [2] f1 6d [2] fe 77 [2] e0 6a [2] e2 6b [2] f9 6d [2] e5 6a [2] f9 45 }

  condition:
    any of them
}