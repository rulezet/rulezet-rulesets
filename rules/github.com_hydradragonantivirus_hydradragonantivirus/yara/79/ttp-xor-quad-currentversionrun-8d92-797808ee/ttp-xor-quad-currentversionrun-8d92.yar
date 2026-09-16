rule TTP_XOR_QUAD_CurrentVersionRun_8d92 {
  strings:
    $key_8d92 = { de fd [2] fa f3 [2] d1 df [2] ff fd [2] eb e6 [2] e4 fc [2] fa e1 [2] f8 e0 [2] e3 e6 [2] ff e1 [2] e3 ce }

  condition:
    any of them
}