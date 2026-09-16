rule TTP_XOR_QUAD_CurrentVersionRun_8b92 {
  strings:
    $key_8b92 = { d8 fd [2] fc f3 [2] d7 df [2] f9 fd [2] ed e6 [2] e2 fc [2] fc e1 [2] fe e0 [2] e5 e6 [2] f9 e1 [2] e5 ce }

  condition:
    any of them
}