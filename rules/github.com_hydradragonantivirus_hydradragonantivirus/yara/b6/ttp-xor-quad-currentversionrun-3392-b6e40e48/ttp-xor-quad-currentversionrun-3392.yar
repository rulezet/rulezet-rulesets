rule TTP_XOR_QUAD_CurrentVersionRun_3392 {
  strings:
    $key_3392 = { 60 fd [2] 44 f3 [2] 6f df [2] 41 fd [2] 55 e6 [2] 5a fc [2] 44 e1 [2] 46 e0 [2] 5d e6 [2] 41 e1 [2] 5d ce }

  condition:
    any of them
}