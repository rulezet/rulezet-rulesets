rule TTP_XOR_QUAD_CurrentVersionRun_9726 {
  strings:
    $key_9726 = { c4 49 [2] e0 47 [2] cb 6b [2] e5 49 [2] f1 52 [2] fe 48 [2] e0 55 [2] e2 54 [2] f9 52 [2] e5 55 [2] f9 7a }

  condition:
    any of them
}