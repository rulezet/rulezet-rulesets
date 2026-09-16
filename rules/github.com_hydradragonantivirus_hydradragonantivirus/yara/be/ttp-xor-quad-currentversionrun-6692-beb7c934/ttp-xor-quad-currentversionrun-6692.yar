rule TTP_XOR_QUAD_CurrentVersionRun_6692 {
  strings:
    $key_6692 = { 35 fd [2] 11 f3 [2] 3a df [2] 14 fd [2] 00 e6 [2] 0f fc [2] 11 e1 [2] 13 e0 [2] 08 e6 [2] 14 e1 [2] 08 ce }

  condition:
    any of them
}