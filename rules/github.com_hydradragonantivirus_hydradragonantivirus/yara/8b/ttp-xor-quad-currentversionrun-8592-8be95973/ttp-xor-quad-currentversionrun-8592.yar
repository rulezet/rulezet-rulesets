rule TTP_XOR_QUAD_CurrentVersionRun_8592 {
  strings:
    $key_8592 = { d6 fd [2] f2 f3 [2] d9 df [2] f7 fd [2] e3 e6 [2] ec fc [2] f2 e1 [2] f0 e0 [2] eb e6 [2] f7 e1 [2] eb ce }

  condition:
    any of them
}