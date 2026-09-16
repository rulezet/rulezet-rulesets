rule TTP_XOR_QUAD_CurrentVersionRun_5592 {
  strings:
    $key_5592 = { 06 fd [2] 22 f3 [2] 09 df [2] 27 fd [2] 33 e6 [2] 3c fc [2] 22 e1 [2] 20 e0 [2] 3b e6 [2] 27 e1 [2] 3b ce }

  condition:
    any of them
}