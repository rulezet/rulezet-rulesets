rule TTP_XOR_QUAD_CurrentVersionRun_2a92 {
  strings:
    $key_2a92 = { 79 fd [2] 5d f3 [2] 76 df [2] 58 fd [2] 4c e6 [2] 43 fc [2] 5d e1 [2] 5f e0 [2] 44 e6 [2] 58 e1 [2] 44 ce }

  condition:
    any of them
}