rule TTP_XOR_QUAD_CurrentVersionRun_9777 {
  strings:
    $key_9777 = { c4 18 [2] e0 16 [2] cb 3a [2] e5 18 [2] f1 03 [2] fe 19 [2] e0 04 [2] e2 05 [2] f9 03 [2] e5 04 [2] f9 2b }

  condition:
    any of them
}