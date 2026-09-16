rule TTP_XOR_QUAD_CurrentVersionRun_9736 {
  strings:
    $key_9736 = { c4 59 [2] e0 57 [2] cb 7b [2] e5 59 [2] f1 42 [2] fe 58 [2] e0 45 [2] e2 44 [2] f9 42 [2] e5 45 [2] f9 6a }

  condition:
    any of them
}