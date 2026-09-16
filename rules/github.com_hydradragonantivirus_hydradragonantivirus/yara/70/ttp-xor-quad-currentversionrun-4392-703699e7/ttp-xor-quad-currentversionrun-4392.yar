rule TTP_XOR_QUAD_CurrentVersionRun_4392 {
  strings:
    $key_4392 = { 10 fd [2] 34 f3 [2] 1f df [2] 31 fd [2] 25 e6 [2] 2a fc [2] 34 e1 [2] 36 e0 [2] 2d e6 [2] 31 e1 [2] 2d ce }

  condition:
    any of them
}