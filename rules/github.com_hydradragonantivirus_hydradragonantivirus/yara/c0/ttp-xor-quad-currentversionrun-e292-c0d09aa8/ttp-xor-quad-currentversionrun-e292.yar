rule TTP_XOR_QUAD_CurrentVersionRun_e292 {
  strings:
    $key_e292 = { b1 fd [2] 95 f3 [2] be df [2] 90 fd [2] 84 e6 [2] 8b fc [2] 95 e1 [2] 97 e0 [2] 8c e6 [2] 90 e1 [2] 8c ce }

  condition:
    any of them
}