rule TTP_XOR_QUAD_CurrentVersionRun_9992 {
  strings:
    $key_9992 = { ca fd [2] ee f3 [2] c5 df [2] eb fd [2] ff e6 [2] f0 fc [2] ee e1 [2] ec e0 [2] f7 e6 [2] eb e1 [2] f7 ce }

  condition:
    any of them
}