rule TTP_XOR_QUAD_CurrentVersionRun_9492 {
  strings:
    $key_9492 = { c7 fd [2] e3 f3 [2] c8 df [2] e6 fd [2] f2 e6 [2] fd fc [2] e3 e1 [2] e1 e0 [2] fa e6 [2] e6 e1 [2] fa ce }

  condition:
    any of them
}