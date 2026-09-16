rule TTP_XOR_QUAD_CurrentVersionRun_7a92 {
  strings:
    $key_7a92 = { 29 fd [2] 0d f3 [2] 26 df [2] 08 fd [2] 1c e6 [2] 13 fc [2] 0d e1 [2] 0f e0 [2] 14 e6 [2] 08 e1 [2] 14 ce }

  condition:
    any of them
}