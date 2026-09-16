rule TTP_XOR_QUAD_CurrentVersionRun_9c92 {
  strings:
    $key_9c92 = { cf fd [2] eb f3 [2] c0 df [2] ee fd [2] fa e6 [2] f5 fc [2] eb e1 [2] e9 e0 [2] f2 e6 [2] ee e1 [2] f2 ce }

  condition:
    any of them
}