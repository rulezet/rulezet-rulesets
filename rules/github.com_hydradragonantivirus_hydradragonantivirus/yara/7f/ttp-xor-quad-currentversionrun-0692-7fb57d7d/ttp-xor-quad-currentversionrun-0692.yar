rule TTP_XOR_QUAD_CurrentVersionRun_0692 {
  strings:
    $key_0692 = { 55 fd [2] 71 f3 [2] 5a df [2] 74 fd [2] 60 e6 [2] 6f fc [2] 71 e1 [2] 73 e0 [2] 68 e6 [2] 74 e1 [2] 68 ce }

  condition:
    any of them
}