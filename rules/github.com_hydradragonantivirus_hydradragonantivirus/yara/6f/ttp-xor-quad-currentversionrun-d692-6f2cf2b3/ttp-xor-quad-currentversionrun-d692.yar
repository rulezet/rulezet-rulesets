rule TTP_XOR_QUAD_CurrentVersionRun_d692 {
  strings:
    $key_d692 = { 85 fd [2] a1 f3 [2] 8a df [2] a4 fd [2] b0 e6 [2] bf fc [2] a1 e1 [2] a3 e0 [2] b8 e6 [2] a4 e1 [2] b8 ce }

  condition:
    any of them
}