rule TTP_XOR_QUAD_CurrentVersionRun_9b92 {
  strings:
    $key_9b92 = { c8 fd [2] ec f3 [2] c7 df [2] e9 fd [2] fd e6 [2] f2 fc [2] ec e1 [2] ee e0 [2] f5 e6 [2] e9 e1 [2] f5 ce }

  condition:
    any of them
}