rule TTP_XOR_QUAD_CurrentVersionRun_f292 {
  strings:
    $key_f292 = { a1 fd [2] 85 f3 [2] ae df [2] 80 fd [2] 94 e6 [2] 9b fc [2] 85 e1 [2] 87 e0 [2] 9c e6 [2] 80 e1 [2] 9c ce }

  condition:
    any of them
}