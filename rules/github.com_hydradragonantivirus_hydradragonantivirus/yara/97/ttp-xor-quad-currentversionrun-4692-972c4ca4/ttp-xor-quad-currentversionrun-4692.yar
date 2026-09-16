rule TTP_XOR_QUAD_CurrentVersionRun_4692 {
  strings:
    $key_4692 = { 15 fd [2] 31 f3 [2] 1a df [2] 34 fd [2] 20 e6 [2] 2f fc [2] 31 e1 [2] 33 e0 [2] 28 e6 [2] 34 e1 [2] 28 ce }

  condition:
    any of them
}