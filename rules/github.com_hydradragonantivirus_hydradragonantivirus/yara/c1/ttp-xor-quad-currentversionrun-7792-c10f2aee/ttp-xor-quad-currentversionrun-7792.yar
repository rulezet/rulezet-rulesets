rule TTP_XOR_QUAD_CurrentVersionRun_7792 {
  strings:
    $key_7792 = { 24 fd [2] 00 f3 [2] 2b df [2] 05 fd [2] 11 e6 [2] 1e fc [2] 00 e1 [2] 02 e0 [2] 19 e6 [2] 05 e1 [2] 19 ce }

  condition:
    any of them
}