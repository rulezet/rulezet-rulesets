rule TTP_XOR_QUAD_CurrentVersionRun_6392 {
  strings:
    $key_6392 = { 30 fd [2] 14 f3 [2] 3f df [2] 11 fd [2] 05 e6 [2] 0a fc [2] 14 e1 [2] 16 e0 [2] 0d e6 [2] 11 e1 [2] 0d ce }

  condition:
    any of them
}