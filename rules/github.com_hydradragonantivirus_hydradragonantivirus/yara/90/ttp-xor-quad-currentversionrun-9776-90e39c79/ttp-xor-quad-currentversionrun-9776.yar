rule TTP_XOR_QUAD_CurrentVersionRun_9776 {
  strings:
    $key_9776 = { c4 19 [2] e0 17 [2] cb 3b [2] e5 19 [2] f1 02 [2] fe 18 [2] e0 05 [2] e2 04 [2] f9 02 [2] e5 05 [2] f9 2a }

  condition:
    any of them
}