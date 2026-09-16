rule TTP_XOR_QUAD_CurrentVersionRun_8192 {
  strings:
    $key_8192 = { d2 fd [2] f6 f3 [2] dd df [2] f3 fd [2] e7 e6 [2] e8 fc [2] f6 e1 [2] f4 e0 [2] ef e6 [2] f3 e1 [2] ef ce }

  condition:
    any of them
}