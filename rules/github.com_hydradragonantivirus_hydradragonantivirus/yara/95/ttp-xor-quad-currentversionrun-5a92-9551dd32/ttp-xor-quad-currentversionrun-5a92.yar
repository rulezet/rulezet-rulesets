rule TTP_XOR_QUAD_CurrentVersionRun_5a92 {
  strings:
    $key_5a92 = { 09 fd [2] 2d f3 [2] 06 df [2] 28 fd [2] 3c e6 [2] 33 fc [2] 2d e1 [2] 2f e0 [2] 34 e6 [2] 28 e1 [2] 34 ce }

  condition:
    any of them
}