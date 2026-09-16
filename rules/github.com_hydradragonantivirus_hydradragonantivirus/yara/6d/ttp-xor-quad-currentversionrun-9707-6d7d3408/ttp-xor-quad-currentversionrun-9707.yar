rule TTP_XOR_QUAD_CurrentVersionRun_9707 {
  strings:
    $key_9707 = { c4 68 [2] e0 66 [2] cb 4a [2] e5 68 [2] f1 73 [2] fe 69 [2] e0 74 [2] e2 75 [2] f9 73 [2] e5 74 [2] f9 5b }

  condition:
    any of them
}