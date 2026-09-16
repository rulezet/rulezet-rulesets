rule TTP_XOR_QUAD_CurrentVersionRun_8292 {
  strings:
    $key_8292 = { d1 fd [2] f5 f3 [2] de df [2] f0 fd [2] e4 e6 [2] eb fc [2] f5 e1 [2] f7 e0 [2] ec e6 [2] f0 e1 [2] ec ce }

  condition:
    any of them
}