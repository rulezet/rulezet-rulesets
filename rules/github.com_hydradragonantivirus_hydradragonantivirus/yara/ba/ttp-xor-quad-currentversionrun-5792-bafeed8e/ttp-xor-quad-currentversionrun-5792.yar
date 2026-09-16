rule TTP_XOR_QUAD_CurrentVersionRun_5792 {
  strings:
    $key_5792 = { 04 fd [2] 20 f3 [2] 0b df [2] 25 fd [2] 31 e6 [2] 3e fc [2] 20 e1 [2] 22 e0 [2] 39 e6 [2] 25 e1 [2] 39 ce }

  condition:
    any of them
}