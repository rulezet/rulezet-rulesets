rule TTP_XOR_QUAD_CurrentVersionRun_f592 {
  strings:
    $key_f592 = { a6 fd [2] 82 f3 [2] a9 df [2] 87 fd [2] 93 e6 [2] 9c fc [2] 82 e1 [2] 80 e0 [2] 9b e6 [2] 87 e1 [2] 9b ce }

  condition:
    any of them
}