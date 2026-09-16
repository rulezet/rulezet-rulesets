rule TTP_XOR_QUAD_CurrentVersionRun_5392 {
  strings:
    $key_5392 = { 00 fd [2] 24 f3 [2] 0f df [2] 21 fd [2] 35 e6 [2] 3a fc [2] 24 e1 [2] 26 e0 [2] 3d e6 [2] 21 e1 [2] 3d ce }

  condition:
    any of them
}