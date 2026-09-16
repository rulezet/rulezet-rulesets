rule TTP_XOR_QUAD_CurrentVersionRun_5b92 {
  strings:
    $key_5b92 = { 08 fd [2] 2c f3 [2] 07 df [2] 29 fd [2] 3d e6 [2] 32 fc [2] 2c e1 [2] 2e e0 [2] 35 e6 [2] 29 e1 [2] 35 ce }

  condition:
    any of them
}