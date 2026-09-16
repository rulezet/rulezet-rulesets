rule TTP_XOR_QUAD_CurrentVersionRun_f792 {
  strings:
    $key_f792 = { a4 fd [2] 80 f3 [2] ab df [2] 85 fd [2] 91 e6 [2] 9e fc [2] 80 e1 [2] 82 e0 [2] 99 e6 [2] 85 e1 [2] 99 ce }

  condition:
    any of them
}