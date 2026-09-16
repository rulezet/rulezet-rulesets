rule TTP_XOR_QUAD_CurrentVersionRun_8992 {
  strings:
    $key_8992 = { da fd [2] fe f3 [2] d5 df [2] fb fd [2] ef e6 [2] e0 fc [2] fe e1 [2] fc e0 [2] e7 e6 [2] fb e1 [2] e7 ce }

  condition:
    any of them
}