rule TTP_XOR_QUAD_CurrentVersionRun_9f92 {
  strings:
    $key_9f92 = { cc fd [2] e8 f3 [2] c3 df [2] ed fd [2] f9 e6 [2] f6 fc [2] e8 e1 [2] ea e0 [2] f1 e6 [2] ed e1 [2] f1 ce }

  condition:
    any of them
}