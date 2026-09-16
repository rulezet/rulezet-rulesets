rule TTP_XOR_QUAD_CurrentVersionRun_8392 {
  strings:
    $key_8392 = { d0 fd [2] f4 f3 [2] df df [2] f1 fd [2] e5 e6 [2] ea fc [2] f4 e1 [2] f6 e0 [2] ed e6 [2] f1 e1 [2] ed ce }

  condition:
    any of them
}