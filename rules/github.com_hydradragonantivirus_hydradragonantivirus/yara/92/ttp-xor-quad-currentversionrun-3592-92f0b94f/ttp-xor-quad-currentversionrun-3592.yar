rule TTP_XOR_QUAD_CurrentVersionRun_3592 {
  strings:
    $key_3592 = { 66 fd [2] 42 f3 [2] 69 df [2] 47 fd [2] 53 e6 [2] 5c fc [2] 42 e1 [2] 40 e0 [2] 5b e6 [2] 47 e1 [2] 5b ce }

  condition:
    any of them
}