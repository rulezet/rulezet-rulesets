rule TTP_XOR_QUAD_CurrentVersionRun_0b92 {
  strings:
    $key_0b92 = { 58 fd [2] 7c f3 [2] 57 df [2] 79 fd [2] 6d e6 [2] 62 fc [2] 7c e1 [2] 7e e0 [2] 65 e6 [2] 79 e1 [2] 65 ce }

  condition:
    any of them
}