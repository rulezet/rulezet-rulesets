rule TTP_XOR_QUAD_CurrentVersionRun_0592 {
  strings:
    $key_0592 = { 56 fd [2] 72 f3 [2] 59 df [2] 77 fd [2] 63 e6 [2] 6c fc [2] 72 e1 [2] 70 e0 [2] 6b e6 [2] 77 e1 [2] 6b ce }

  condition:
    any of them
}