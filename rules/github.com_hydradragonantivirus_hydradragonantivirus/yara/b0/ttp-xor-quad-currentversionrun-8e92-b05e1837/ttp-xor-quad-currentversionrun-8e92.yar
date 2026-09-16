rule TTP_XOR_QUAD_CurrentVersionRun_8e92 {
  strings:
    $key_8e92 = { dd fd [2] f9 f3 [2] d2 df [2] fc fd [2] e8 e6 [2] e7 fc [2] f9 e1 [2] fb e0 [2] e0 e6 [2] fc e1 [2] e0 ce }

  condition:
    any of them
}