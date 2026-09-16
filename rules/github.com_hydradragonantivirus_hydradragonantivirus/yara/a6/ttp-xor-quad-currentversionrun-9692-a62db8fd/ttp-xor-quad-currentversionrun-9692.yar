rule TTP_XOR_QUAD_CurrentVersionRun_9692 {
  strings:
    $key_9692 = { c5 fd [2] e1 f3 [2] ca df [2] e4 fd [2] f0 e6 [2] ff fc [2] e1 e1 [2] e3 e0 [2] f8 e6 [2] e4 e1 [2] f8 ce }

  condition:
    any of them
}