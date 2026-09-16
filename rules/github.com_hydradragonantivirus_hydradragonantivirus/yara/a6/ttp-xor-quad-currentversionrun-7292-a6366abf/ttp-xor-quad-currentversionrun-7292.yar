rule TTP_XOR_QUAD_CurrentVersionRun_7292 {
  strings:
    $key_7292 = { 21 fd [2] 05 f3 [2] 2e df [2] 00 fd [2] 14 e6 [2] 1b fc [2] 05 e1 [2] 07 e0 [2] 1c e6 [2] 00 e1 [2] 1c ce }

  condition:
    any of them
}