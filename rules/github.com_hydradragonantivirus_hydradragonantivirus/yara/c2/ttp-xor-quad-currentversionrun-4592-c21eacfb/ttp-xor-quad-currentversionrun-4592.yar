rule TTP_XOR_QUAD_CurrentVersionRun_4592 {
  strings:
    $key_4592 = { 16 fd [2] 32 f3 [2] 19 df [2] 37 fd [2] 23 e6 [2] 2c fc [2] 32 e1 [2] 30 e0 [2] 2b e6 [2] 37 e1 [2] 2b ce }

  condition:
    any of them
}