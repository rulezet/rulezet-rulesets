rule TTP_XOR_QUAD_CurrentVersionRun_9792 {
  strings:
    $key_9792 = { c4 fd [2] e0 f3 [2] cb df [2] e5 fd [2] f1 e6 [2] fe fc [2] e0 e1 [2] e2 e0 [2] f9 e6 [2] e5 e1 [2] f9 ce }

  condition:
    any of them
}