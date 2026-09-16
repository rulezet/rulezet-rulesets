rule TTP_XOR_QUAD_CurrentVersionRun_7b92 {
  strings:
    $key_7b92 = { 28 fd [2] 0c f3 [2] 27 df [2] 09 fd [2] 1d e6 [2] 12 fc [2] 0c e1 [2] 0e e0 [2] 15 e6 [2] 09 e1 [2] 15 ce }

  condition:
    any of them
}