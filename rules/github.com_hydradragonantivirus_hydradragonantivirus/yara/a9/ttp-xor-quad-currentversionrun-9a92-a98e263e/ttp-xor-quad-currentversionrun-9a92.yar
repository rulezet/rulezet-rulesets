rule TTP_XOR_QUAD_CurrentVersionRun_9a92 {
  strings:
    $key_9a92 = { c9 fd [2] ed f3 [2] c6 df [2] e8 fd [2] fc e6 [2] f3 fc [2] ed e1 [2] ef e0 [2] f4 e6 [2] e8 e1 [2] f4 ce }

  condition:
    any of them
}