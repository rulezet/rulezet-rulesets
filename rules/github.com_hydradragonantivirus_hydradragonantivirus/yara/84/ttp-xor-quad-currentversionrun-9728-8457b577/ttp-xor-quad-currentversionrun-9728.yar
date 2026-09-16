rule TTP_XOR_QUAD_CurrentVersionRun_9728 {
  strings:
    $key_9728 = { c4 47 [2] e0 49 [2] cb 65 [2] e5 47 [2] f1 5c [2] fe 46 [2] e0 5b [2] e2 5a [2] f9 5c [2] e5 5b [2] f9 74 }

  condition:
    any of them
}